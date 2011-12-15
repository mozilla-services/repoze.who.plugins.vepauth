# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is repoze.who.plugins.browserid4sync
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

A repoze.who plugin for authentication via BrowserID and OAuth signatures.
It's experimental and designed for use by the next version of Firefox Sync.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


import re
import fnmatch

from zope.interface import implements

from webob import Request, Response

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.utils import resolveDotted

import vep

from repoze.who.plugins.browserid4sync.tokenmanager import SignedTokenManager
from repoze.who.plugins.browserid4sync.utils import parse_assertion


class BrowserID4SyncPlugin(object):

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, audiences, token_url=None, token_manager=None,
                 verifier=None):
        if token_url is None:
            token_url = "/token"
        if token_manager is None:
            token_manager = SignedTokenManager()
        if verifier is None:
            verifier = vep.RemoteVerifier()
        self.audiences = audiences
        if audiences:
            audience_patterns = map(self._compile_audience_pattern, audiences)
            self._audience_patterns = audience_patterns
        self.token_url = token_url
        self.token_manager = token_manager
        self.verifier = verifier

    def identify(self, environ):
        request = Request(environ)
        # If we're at the token URL then process the login and
        # assign a new set of credentials.  This will always result
        # in setting environ["repoze.who.application"].
        if request.path == self.token_path:
            # You must provision a token using POST.
            if request.method != "POST":
                return self._do_bad_request(request, "must use POST")
            # Grab the assertion from the POST body.
            assertion = request.POST.get("assertion")
            if assertion is None:
                return self._do_bad_request(request, "no assertion")
            # Extract the audience, so we can check against wildcards.
            try:
                audience = parse_assertion(assertion)["audience"]
            except (ValueError, KeyError):
                return self._do_bad_request(request, "invalid assertion")
            if not self._check_audience(request, audience):
                msg = "The audience \"%s\" is not recognised" % (audience,)
                return self._do_bad_request(request, msg)
            # Verify the assertion and find out who they are.
            try:
                data = self.verifier.verify(assertion)
            except Exception:
                msg = "Invalid BrowserID assertion"
                return self._do_bad_request(request, msg)
            # OK, we can go ahead and issue a token.
            token, secret = self.token_manager.make_token(data["email"])
            resp = Response()
            resp.status = 200
            resp.content = "oauth_token=%s&oauth_secret=%s" % (token, secret)
            request.environ["repoze.who.application"] = resp
            return None
        # Otherwise, extract OAuth signed request details.
        # TODO: the whole "signing" thing.
        return None

    def remember(self, environ, identity):
        return []

    def forget(self, environ, identity):
        return []

    def challenge(self, environ, status, app_headers=(), forget_headers=()):
        # TODO: somewhere we need to send a 401 with WWW-Authenticate: OAuth
        return None

    def authenticate(self, environ, identity):
        # TODO: the whole "signing" thing.
        return None

    def _check_audience(self, request, audience):
        """Check that the audience is valid according to our configuration.

        This function uses the configured list of valid audience patterns to
        verify the given audience.  If no audience values have been configured
        then it matches against the Host header from the request.
        """
        if not self.audiences:
            return audience == request.host_url
        for audience_pattern in self._audience_patterns:
            if audience_pattern.match(audience):
                return True
        return False

    def _compile_audience_pattern(self, pattern):
        """Compile a glob-style audience pattern into a regular expression."""
        re_pattern = fnmatch.translate(pattern)
        if "://" not in pattern:
            re_pattern = "[a-z]+://" + re_pattern
        return re.compile(re_pattern)

    def _do_bad_request(self, request, message="Bad Request"):
        assert request.path == self.token_url
        error_resp = Response
        error_resp.status = 400
        error_resp.content = message
        request.environ["repoze.who.application"] = error_resp
        return None


def make_plugin(audiences, token_url=None, token_manager=None,
                verifier=None, **kwds):
    """Make a BrowserID4SyncPlugin using values from a .ini config file.

    This is a helper function for loading a BrowserID4SyncPlugin via the
    repoze.who .ini config file system. It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    if not audiences:
        audiences = None
    elif isinstance(audiences, basestring):
        audiences = audiences.split()
    if isinstance(verifier, basestring):
        verifier = resolveDotted(verifier)
        if callable(verifier):
            verifier_kwds = {}
            for key, value in kwds.iteritems():
                if key == "verifier_urlopen":
                    value = resolveDotted(value)
                if key.startswith("verifier_"):
                    verifier_kwds[key[len("verifier_"):]] = value
            verifier = verifier(**verifier_kwds)
    plugin = BrowserID4SyncPlugin(audiences, token_url, token_manager,
                                  verifier)
    return plugin
