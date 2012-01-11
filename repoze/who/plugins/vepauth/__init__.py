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
# The Original Code is repoze.who.plugins.vepauth
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
from urlparse import urljoin

from zope.interface import implements

from webob import Request, Response

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.utils import resolveDotted

import vep
from vep.utils import get_assertion_info

from repoze.who.plugins.vepauth.tokenmanager import SignedTokenManager
from repoze.who.plugins.vepauth.utils import (strings_differ,
                                              parse_authz_header,
                                              NonceCache)


class VEPAuthPlugin(object):

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, audiences, token_url=None, token_manager=None,
                 verifier=None, nonce_timeout=None):
        if isinstance(audiences, basestring):
           raise ValueError("\"audiences\" must be a list of strings")
        # Fill in default values for any unspecified arguments.
        # I'm not declaring defaults on the arguments themselves because
        # we would then have to duplicate those defaults into make_plugin.
        if token_url is None:
            token_url = "/request_token"
        if token_manager is None:
            token_manager = SignedTokenManager()
        if verifier is None:
            verifier = vep.RemoteVerifier()
        if nonce_timeout is None:
            nonce_timeout = 5 * 60
        # Now we can initialize.
        self.audiences = audiences
        if audiences:
            audience_patterns = map(self._compile_audience_pattern, audiences)
            self._audience_patterns = audience_patterns
        self.token_url = token_url
        self.token_manager = token_manager
        self.verifier = verifier
        self.nonce_timeout = nonce_timeout
        self.nonce_cache = NonceCache(nonce_timeout)

    def identify(self, environ):
        """Extract the authentication info from the request.

        If this is a request to the token-provisioning URL then we extract
        a posted BrowserID assertion and exchange it for a new session token,
        setting environ["repoze.who.application"] to pass the details back
        to the caller.

        For all other URLs, we extract the OAuth params from the Authorization
        header and return those as the identity.
        """
        request = Request(environ)
        if self._is_request_to_token_url(request):
            return self._process_vep_assertion(request)
        return self._identify_oauth(request)

    def remember(self, environ, identity):
        """Remember the user's identity.

        This is a no-op for this plugin; the client is supposed to remember
        the provisioned OAuth credentials and re-use them for subsequent
        requests.
        """
        return []

    def forget(self, environ, identity):
        """Forget the user's identity.

        This simply issues a new WWW-Authenticate challenge, which should
        cause the client to forget any previously-provisioned credentials.
        """
        challenge = "OAuth+VEP url=\"%s\"" % (self.token_url,)
        return [("WWW-Authenticate", challenge)]

    def challenge(self, environ, status, app_headers=(), forget_headers=()):
        """Challenge the user for credentials.

        This simply sends a 401 response using the WWW-Authenticate field
        as constructed by forget(). 
        """
        headers = self.forget(environ, {})
        headers.append(("Content-Type", "text/plain"))
        headers.extend(app_headers)
        headers.extend(forget_headers)
        if not status.startswith("401 "):
            status = "401 Unauthorized"

        def challenge_app(environ, start_response):
            start_response(status, headers)
            return ["Unauthorized"]

        return challenge_app

    def authenticate(self, environ, identity):
        """Authenticate the extracted identity.

        The identity must be a set of OAuth credentials extracted from
        the request.  This method checks the OAuth signature, and if valid
        extracts the user metadata from the token.
        """
        request = Request(environ)
        assert not self._is_request_to_token_url(request)
        return self._authenticate_oauth(request)

    #
    #  Methods for exchanging an assertion for an OAuth session token.
    #

    def _process_vep_assertion(self, request): 
        # You must provision a token using POST.
        if request.method != "POST":
            return self._do_bad_request(request, "must use POST")
        # Grab the assertion from the POST body.
        assertion = request.POST.get("assertion")
        if assertion is None:
            return self._do_bad_request(request, "no assertion")
        # Extract the audience, so we can check against wildcards.
        try:
            audience = get_assertion_info(assertion)["audience"]
        except (ValueError, KeyError):
            return self._do_bad_request(request, "invalid assertion")
        if not self._check_audience(request, audience):
            msg = "The audience \"%s\" is not acceptable" % (audience,)
            return self._do_bad_request(request, msg.encode("utf8"))
        # Verify the assertion and find out who they are.
        try:
            data = self.verifier.verify(assertion)
        except Exception, e:
            msg = "Invalid BrowserID assertion: " + str(e)
            return self._do_bad_request(request, msg)
        # OK, we can go ahead and issue a token.
        token, secret = self.token_manager.make_token(data)
        resp = Response()
        resp.status = 200
        resp.body = "oauth_token=%s&oauth_secret=%s" % (token, secret)
        request.environ["repoze.who.application"] = resp
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

    #
    #  Methods for Two-Legged OAuth once the assertion has been verified.
    #

    def _identify_oauth(self, request):
        """Parse, validate and return the request Authorization header.

        This method grabs the OAuth credentials from the Authorization header
        and performs some sanity-checks.  If the credentials are missing or
        malformed then it returns None; if they're ok then they are returned
        in a dict.

        Note that this method does *not* validate the OAuth signature.
        """
        params = parse_authz_header(request, None)
        if params is None:
            return None
        # Check that various parameters are as expected.
        if params.get("scheme") != "OAuth":
            return None
        if params.get("oauth_signature_method") != "HMAC-SHA1":
            return None
        if "oauth_consumer_key" not in params:
            return None
        # Check the timestamp, reject if too far from current time.
        try:
            timestamp = int(params["oauth_timestamp"])
        except (KeyError, ValueError):
            return None
        if abs(timestamp - time.time()) >= self.nonce_timeout:
            return None
        # Check that the nonce is not being re-used.
        nonce = params.get("oauth_nonce")
        if nonce is None:
            return None
        if nonce in self.nonce_cache:
            return None
        # OK, they seem like sensible OAuth paramters.
        return params

    def _authenticate_oauth(self, environ, identity):
        # We can only authenticate if it has a valid oauth token.
        token = identity.get("oauth_consumer_key")
        if not token:
            return None
        try:
            data, secret = self.token_manager.parse_token(token)
        except ValueError:
            return None
        # Check the two-legged OAuth signature.
        sigdata = self._get_oauth_sigdata(request)
        expected_sig = b64encode(hmac.new(secret, sigdata, sha1).digest())
        if strings_differ(identity["oauth_signature"], expected_sig):
            return None
        # Cache the nonce to avoid re-use.
        # We do this *after* successul auth to avoid DOS attacks.
        nonce = identity["oauth_nonce"]
        timestamp = int(identity["oauth_timestamp"])
        self.nonce_cache.add(nonce, timestamp)
        # Update the identity with the data from the token.
        identity.update(data)
        return identity["repoze.who.userid"]

    def _get_oauth_sigdata(self, request):
        """Get the data to be signed for OAuth authentication.

        This method takes a request object and returns the data that should
        be signed for OAuth authentication of that request.  This data is the
        "signature base string" as defined in section 3.4.1 of RFC-5849.
        """
        bits = []
        # The request method in upper-case.
        bits.append(request.method.upper())
        # The base string URI. TODO: figure out encoding
        uri = request.path_url
        host_len = len(request.host_url)
        uri = uri[:host_len].lower() + uri[host_len:]
        bits.append(uri)
        # The request parameters.
        # TODO: encoding;
        params = request.GET.items()
        if request.content_type == "application/x-www-form-urlencoded":
            params.extend(request.POST.items())
        for item in parse_authz_header(request, {}).iteritems():
            if item[0] not in ("scheme", "oauth_signature"):
                params.append(item)
        params.sort()
        bits.append("&".join("%s=%s" % (k, v) for k, v in params))
        return "&".join(bits)

    #
    #  Misc helper methods.
    #

    def _do_bad_request(self, request, message="Bad Request"):
        """Generate a "400 Bad Request" error response."""
        error_resp = Response()
        error_resp.status = 400
        error_resp.body = message
        request.environ["repoze.who.application"] = error_resp
        return None

    def _is_request_to_token_url(self, request):
        """Check if given request is to the token-provisioning URL."""
        request_url =  urljoin(request.host_url, request.path)
        return request_url == urljoin(request.host_url, self.token_url)


def make_plugin(audiences=None, token_url=None, nonce_timeout=None, **kwds):
    """Make a VEPAuthPlugin using values from a .ini config file.

    This is a helper function for loading a VEPAuthPlugin via the
    repoze.who .ini config file system. It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    # You *must* specify the "audiences" parameter since it's integral
    # to the security of the protocol.  If you want it set to None to
    # allow checking based on HTTP_HOST, set it to the empty string.
    if audiences is None:
         raise ValueError('You must specify the "audiences" parameter')
    if not audiences:
        audiences = None
    elif isinstance(audiences, basestring):
        audiences = audiences.split()
    # Load the token manager, possibly from a class+args.
    token_manager = _load_from_callable("token_manager", kwds)
    # Load the VEP verifier, possibly from a class+args.
    # Assume "urlopen" is a dotted-name of a callable.
    verifier = _load_from_callable("verifier", kwds, converters={
        "urlopen": resolveDotted
    })
    # If there are any kwd args left over, that's an error.
    for unknown_kwd in kwds:
        raise TypeError("unknown keyword argument: %s" % (unknown_kwd,))
    plugin = VEPAuthPlugin(audiences, token_url, token_manager, verifier,
                           nonce_timeout)
    return plugin


def _load_from_callable(name, kwds, converters={}):
    """Load a plugin argument from dotted python name of callable.

    This function is a helper to load and possibly instanciate an argument
    to the plugin.  It grabs the value from the dotted python name found in
    kwds[name].  If this is a callable, it it looks for arguments of the form 
    kwds[name_*] and calls the object with them.
    """
    # See if we actually have the named object.
    dotted_name = kwds.pop(name, None)
    if dotted_name is None:
        return None
    obj = resolveDotted(dotted_name)
    # Extract any arguments for the callable.
    obj_kwds = {}
    prefix = name+"_"
    for key in kwds.keys():
       if key.startswith(prefix):
            obj_kwds[key[len(prefix):]] = kwds.pop(key)
    # To any type conversion on the arguments.
    for key, value in obj_kwds.iteritems():
        converter = converters.get(key)
        if converter is not None:
            obj_kwds[key] = converter(value)
    # Call it if callable.
    if callable(obj):
        obj = obj(**obj_kwds)
    elif obj_kwds:
        raise ValueError("arguments provided for non-callable %r" % (name,))
    return obj
