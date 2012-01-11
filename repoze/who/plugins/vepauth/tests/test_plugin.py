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

import unittest2
import urllib2
from cStringIO import StringIO

from webob import Request
from webtest import TestApp

from zope.interface.verify import verifyClass

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.middleware import PluggableAuthenticationMiddleware
from repoze.who.classifiers import (default_challenge_decider,
                                    default_request_classifier)

import vep
from vep.utils import get_assertion_info

from repoze.who.plugins.vepauth import VEPAuthPlugin, make_plugin
from repoze.who.plugins.vepauth.tokenmanager import SignedTokenManager
from repoze.who.plugins.vepauth.utils import sign_request


def make_environ(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return environ


def test_application(environ, start_response):
    """Simple WSGI app that requires authentication.

    This is a simple testing app that returns the userid if the environment
    contains a repoze.who identity, and denies access if it does not. URLs
    containing the string "forbidden" will get a 403 response, while other
    URLs will get a 401 response.
    """
    headers = [("Content-Type", "text/plain")]
    if "repoze.who.identity" not in environ:
        if "forbidden" in environ["PATH_INFO"]:
            start_response("403 Forbidden", headers)
        else:
            start_response("401 Unauthorized", headers)
        return ["Unauthorized"]
    start_response("200 OK", headers)
    return [environ["repoze.who.identity"]["repoze.who.userid"].encode("utf8")]


class TestVEPAuthPlugin(unittest2.TestCase):
    """Testcases for the main VEPAuthPlugin class."""

    def setUp(self):
        self.plugin = VEPAuthPlugin(audiences=["localhost"],
                                    verifier=vep.DummyVerifier())
        application = PluggableAuthenticationMiddleware(test_application,
                                 [["vep", self.plugin]],
                                 [["vep", self.plugin]],
                                 [["vep", self.plugin]],
                                 [],
                                 default_request_classifier,
                                 default_challenge_decider)
        self.app = TestApp(application)

    def _make_assertion(self, address, audience="http://localhost", **kwds):
        return vep.DummyVerifier.make_assertion(address, audience, **kwds)

    def test_implements(self):
        verifyClass(IIdentifier, VEPAuthPlugin)
        verifyClass(IAuthenticator, VEPAuthPlugin)
        verifyClass(IChallenger, VEPAuthPlugin)

    def test_make_plugin(self):
        # Test that everything can be set explicitly.
        plugin = make_plugin(
            audiences="example.com",
            token_url="/test_token_url",
            verifier="vep:DummyVerifier",
            token_manager="vep:LocalVerifier",
            nonce_timeout=42)
        self.assertEquals(plugin.audiences, ["example.com"])
        self.assertEquals(plugin.token_url, "/test_token_url")
        self.assertTrue(isinstance(plugin.verifier, vep.DummyVerifier))
        self.assertTrue(isinstance(plugin.token_manager, vep.LocalVerifier))
        self.assertEquals(plugin.nonce_timeout, 42)
        # Test that everything gets a sensible default.
        # Except for "audiences" of course, which you must set explicitly.
        self.assertRaises(ValueError, make_plugin)
        plugin = make_plugin("one two")
        self.assertEquals(plugin.audiences, ["one", "two"])
        self.assertEquals(plugin.token_url, "/request_token")
        self.assertTrue(isinstance(plugin.verifier, vep.RemoteVerifier))
        self.assertTrue(isinstance(plugin.token_manager, SignedTokenManager))
        self.assertEquals(plugin.nonce_timeout, 5 * 60)
        # Check setting of urlopen from a dotted-name string.
        plugin = make_plugin("one two", verifier="vep:LocalVerifier",
                             verifier_urlopen="urllib2:urlopen")
        self.assertEquals(plugin.audiences, ["one", "two"])
        self.assertTrue(isinstance(plugin.verifier, vep.LocalVerifier))
        self.assertEquals(plugin.verifier.urlopen, urllib2.urlopen)

    def test_checking_for_silly_argument_errors(self):
        self.assertRaises(ValueError, VEPAuthPlugin, audiences="notalist")

    def test_remember_does_nothing(self):
        self.assertEquals(self.plugin.remember(make_environ(), {}), [])

    def test_forget_gives_a_challenge_header(self):
        headers = self.plugin.forget(make_environ(), {})
        self.assertEquals(len(headers), 1)
        self.assertEquals(headers[0][0], "WWW-Authenticate")
        self.assertTrue(headers[0][1].startswith("OAuth+VEP "))
        self.assertTrue(self.plugin.token_url in headers[0][1])

    def test_unauthenticated_requests_get_a_challenge(self):
        # Requests to most URLs generate a 401, which is passed through
        # with the appropriate challenge.
        r = self.app.get("/", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("OAuth+VEP"))
        self.assertTrue(self.plugin.token_url in challenge)
        # Requests to URLs with "forbidden" generate a 403 in the downstream
        # app, which should be converted into a 401 by the plugin.
        r = self.app.get("/forbidden", status=401)
        challenge = r.headers["WWW-Authenticate"]
        self.assertTrue(challenge.startswith("OAuth+VEP"))
        self.assertTrue(self.plugin.token_url in challenge)

    def test_posting_an_assertion_creates_a_token(self):
        body = {"assertion": self._make_assertion("test@moz.com")}
        # This fails since we're not at the token-provisioning URL.
        r = self.app.post("/", body, status=401)
        self.assertTrue("oauth_consumer_key" not in r.body)
        # This works since we're at the postback url.
        r = self.app.post(self.plugin.token_url, body)
        self.assertTrue("oauth_consumer_key" in r.body)

    def test_provisioning_with_no_assertion(self):
        r = self.app.post(self.plugin.token_url, {}, status=400)
        self.assertTrue("assertion" in r.body)

    def test_provisioning_with_non_POST_request(self):
        body = {"assertion": self._make_assertion("test@moz.com")}
        r = self.app.put(self.plugin.token_url, body, status=400)
        self.assertTrue("use POST" in r.body)

    def test_provisioning_with_malformed_assertion(self):
        body = {"assertion": "I AINT NO ASSERTION, FOOL!"}
        r = self.app.post(self.plugin.token_url, body, status=400)
        self.assertTrue("assertion" in r.body)

    def test_provisioning_with_untrusted_assertion(self):
        assertion = self._make_assertion("test@moz", assertion_sig="X")
        body = {"assertion": assertion}
        r = self.app.post(self.plugin.token_url, body, status=400)
        self.assertTrue("assertion" in r.body)

    def test_provisioning_with_invalid_audience(self):
        assertion = self._make_assertion("test@moz.com", "http://evil.com")
        body = {"assertion": assertion}
        r = self.app.post(self.plugin.token_url, body, status=400)
        self.assertTrue("audience" in r.body)
        # Setting audiences to None will allow it to pass
        # if it matches the HTTP_HOST header.
        self.plugin.audiences = None
        r = self.app.post(self.plugin.token_url, body, status=400)
        self.assertTrue("audience" in r.body)
        r = self.app.post(self.plugin.token_url, body, extra_environ={
            "HTTP_HOST": "evil.com"
        })
        self.assertTrue("oauth_consumer_key" in r.body)

    def test_authenticated_request_works(self):
        body = {"assertion": self._make_assertion("test@moz.com")}
        session = self.app.post(self.plugin.token_url, body).json
        req = Request.blank("/")
        sign_request(req, **session)
        r = self.app.request(req)
