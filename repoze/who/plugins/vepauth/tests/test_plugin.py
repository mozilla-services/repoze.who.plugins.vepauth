# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest2
import urllib2
import time
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
from repoze.who.plugins.vepauth.utils import sign_request, parse_authz_header


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


def stub_application(environ, start_response):
    """Simple WSGI app that requires authentication.

    This is a simple testing app that returns the userid if the environment
    contains a repoze.who identity, and denies access if it does not. URLs
    containing the string "forbidden" will get a 403 response, while other
    URLs will get a 401 response.

    The special path "/public" can be viewed without authentication.
    """
    headers = [("Content-Type", "text/plain")]
    if environ["PATH_INFO"] == "/public":
        body = "public"
    else:
        if "repoze.who.identity" not in environ:
            if "forbidden" in environ["PATH_INFO"]:
                start_response("403 Forbidden", headers)
            else:
                start_response("401 Unauthorized", headers)
            return ["Unauthorized"]
        body = environ["repoze.who.identity"]["repoze.who.userid"]
        body = body.encode("utf8")
    start_response("200 OK", headers)
    return [body]


def stub_request_classifier(environ):
    """Testing request classifier; all requests are are just 'web' requests."""
    return "web"


def stub_challenge_decider(environ, status, headers):
    """Testing challenge decider; 401 and 403 responses get a challenge."""
    return status.split(None, 1)[0] in ("401", "403")


class StubTokenManager(SignedTokenManager):
    """SignedTokenManager that rejects evil email addresses, for testing."""

    def make_token(self, data):
        if "evil" in data["email"]:
            return None, None
        return super(StubTokenManager, self).make_token(data)


class TestVEPAuthPlugin(unittest2.TestCase):
    """Testcases for the main VEPAuthPlugin class."""

    def setUp(self):
        self.plugin = VEPAuthPlugin(audiences=["localhost"],
                                    verifier=vep.DummyVerifier(),
                                    token_manager=StubTokenManager())
        application = PluggableAuthenticationMiddleware(stub_application,
                                 [["vep", self.plugin]],
                                 [["vep", self.plugin]],
                                 [["vep", self.plugin]],
                                 [],
                                 stub_request_classifier,
                                 stub_challenge_decider)
        self.app = TestApp(application)

    def _make_assertion(self, address, audience="http://localhost", **kwds):
        return vep.DummyVerifier.make_assertion(address, audience, **kwds)

    def _start_session(self, email="test@moz.com", *args, **kwds):
        assertion = self._make_assertion(email, *args, **kwds)
        headers = {"Authorization": "Browser-ID " + assertion}
        session = self.app.get(self.plugin.token_url, headers=headers).json
        return session

    def test_implements(self):
        verifyClass(IIdentifier, VEPAuthPlugin)
        verifyClass(IAuthenticator, VEPAuthPlugin)
        verifyClass(IChallenger, VEPAuthPlugin)

    def test_make_plugin_can_explicitly_set_all_properties(self):
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

    def test_make_plugin_produces_sensible_defaults(self):
        # The "audiences" parameter must be set explicitly
        self.assertRaises(ValueError, make_plugin)
        plugin = make_plugin("one two")
        self.assertEquals(plugin.audiences, ["one", "two"])
        self.assertEquals(plugin.token_url, "/request_token")
        self.assertTrue(isinstance(plugin.verifier, vep.RemoteVerifier))
        self.assertTrue(isinstance(plugin.token_manager, SignedTokenManager))
        self.assertEquals(plugin.nonce_timeout, 5 * 60)

    def test_make_plugin_loads_urlopen_from_dotted_name(self):
        plugin = make_plugin("one two", verifier="vep:LocalVerifier",
                             verifier_urlopen="urllib2:urlopen")
        self.assertEquals(plugin.audiences, ["one", "two"])
        self.assertTrue(isinstance(plugin.verifier, vep.LocalVerifier))
        self.assertEquals(plugin.verifier.urlopen, urllib2.urlopen)

    def test_make_plugin_treats_empty_audiences_string_as_none(self):
        plugin = make_plugin("")
        self.assertEquals(plugin.audiences, None)
        plugin = make_plugin(" ")
        self.assertEquals(plugin.audiences, [])

    def test_make_plugin_errors_out_on_unexpected_keyword_args(self):
        self.assertRaises(TypeError, make_plugin, "",
                                     unexpected="spanish-inquisition")

    def test_make_plugin_errors_out_on_args_to_a_non_callable(self):
        self.assertRaises(ValueError, make_plugin, "",
                                     verifier="vep:__doc__",
                                     verifier_urlopen="urllib2:urlopen")

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

    def test_sending_an_assertion_creates_a_token(self):
        authz = "Browser-ID " + self._make_assertion("test@moz.com")
        headers = {"Authorization": authz}
        # This fails since we're not at the token-provisioning URL.
        r = self.app.get("/", headers=headers, status=401)
        self.assertTrue("oauth_consumer_key" not in r.body)
        # This works since we're at the postback url.
        r = self.app.get(self.plugin.token_url, headers=headers)
        self.assertTrue("oauth_consumer_key" in r.body)

    def test_that_an_empty_token_url_disables_provisioning(self):
        authz = "Browser-ID " + self._make_assertion("test@moz.com")
        headers = {"Authorization": authz}
        self.plugin.token_url = ""
        r = self.app.get("/", headers=headers, status=401)
        self.assertTrue("oauth_consumer_key" not in r.body)
        r = self.app.get("/request_token", headers=headers, status=401)
        self.assertTrue("oauth_consumer_key" not in r.body)

    def test_non_get_requests_give_405(self):
        authz = "Browser-ID " + self._make_assertion("test@moz.com")
        headers = {"Authorization": authz}
        self.app.post(self.plugin.token_url, headers=headers, status=405)

    def test_provisioning_with_malformed_assertion(self):
        authz = "Browser-ID I AINT NO ASSERTION, FOOL!"
        headers = {"Authorization": authz}
        r = self.app.get(self.plugin.token_url, headers=headers, status=400)
        self.assertTrue("assertion" in r.body)

    def test_provisioning_with_no_credentials_gives_401(self):
        headers = {}
        self.app.get(self.plugin.token_url, headers=headers, status=401)

    def test_provisioning_with_basic_credentials_gives_400(self):
        headers = {"Authorization": "Basic dTpw"}
        self.app.get(self.plugin.token_url, headers=headers, status=400)

    def test_provisioning_with_untrusted_assertion(self):
        assertion = self._make_assertion("test@moz", assertion_sig="X")
        headers = {"Authorization": "Browser-ID " + assertion}
        r = self.app.get(self.plugin.token_url, headers=headers, status=400)
        self.assertTrue("assertion" in r.body)

    def test_provisioning_with_invalid_audience(self):
        assertion = self._make_assertion("test@moz.com", "http://evil.com")
        headers = {"Authorization": "Browser-ID " + assertion}
        r = self.app.get(self.plugin.token_url, headers=headers, status=400)
        self.assertTrue("audience" in r.body)
        # Setting audiences to None will allow it to pass
        # if it matches the HTTP_HOST header.
        self.plugin.audiences = None
        r = self.app.get(self.plugin.token_url, headers=headers, status=400)
        self.assertTrue("audience" in r.body)
        r = self.app.get(self.plugin.token_url, headers=headers,
                         extra_environ={"HTTP_HOST": "evil.com"})
        self.assertTrue("oauth_consumer_key" in r.body)

    def test_provisioning_with_unaccepted_email_address(self):
        assertion = self._make_assertion("evil@hacker.net")
        headers = {"Authorization": "Browser-ID " + assertion}
        self.app.get(self.plugin.token_url, headers=headers, status=401)

    def test_authenticated_request_works(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")

    def test_authentication_with_non_oauth_scheme_fails(self):
        req = Request.blank("/")
        req.authorization = "OpenID hello=world"
        self.app.request(req, status=401)

    def test_authentication_with_plaintext_sig_method_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("HMAC-SHA1", "PLAINTEXT")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_consumer_key_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("oauth_consumer_key", "oauth_typo_key")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_timestamp_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("oauth_timestamp", "oauth_typostamp")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_without_nonce_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace("oauth_nonce", "oauth_typonce")
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_expired_timestamp_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        ts = str(int(time.time() - 1000))
        req.authorization = ("OAuth", {"oauth_timestamp": ts})
        sign_request(req, **session)
        self.app.request(req, status=401)

    def test_authentication_with_far_future_timestamp_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        ts = str(int(time.time() + 1000))
        req.authorization = ("OAuth", {"oauth_timestamp": ts})
        sign_request(req, **session)
        self.app.request(req, status=401)

    def test_authentication_with_reused_nonce_fails(self):
        session = self._start_session()
        # First request with that nonce should succeed.
        req = Request.blank("/")
        req.authorization = ("OAuth", {"oauth_nonce": "PEPPER"})
        sign_request(req, **session)
        r = self.app.request(req)
        self.assertEquals(r.body, "test@moz.com")
        # Second request with that nonce should fail.
        req = Request.blank("/")
        req.authorization = ("OAuth", {"oauth_nonce": "PEPPER"})
        sign_request(req, **session)
        self.app.request(req, status=401)

    def test_authentication_with_busted_token_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        token = parse_authz_header(req)["oauth_consumer_key"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(token, "XXX" + token)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_authentication_with_busted_signature_fails(self):
        session = self._start_session()
        req = Request.blank("/")
        sign_request(req, **session)
        signature = parse_authz_header(req)["oauth_signature"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        self.app.request(req, status=401)

    def test_access_to_public_urls(self):
        # Request with no credentials is allowed access.
        req = Request.blank("/public")
        resp = self.app.request(req)
        self.assertEquals(resp.body, "public")
        # Request with valid credentials is allowed access.
        session = self._start_session()
        req = Request.blank("/public")
        sign_request(req, **session)
        resp = self.app.request(req)
        self.assertEquals(resp.body, "public")
        # Request with invalid credentials gets a 401.
        req = Request.blank("/public")
        sign_request(req, **session)
        signature = parse_authz_header(req)["oauth_signature"]
        authz = req.environ["HTTP_AUTHORIZATION"]
        authz = authz.replace(signature, "XXX" + signature)
        req.environ["HTTP_AUTHORIZATION"] = authz
        resp = self.app.request(req, status=401)

    def test_authenticate_only_accepts_oauth_credentials(self):
        # Yes, this is a rather pointless test that boosts line coverage...
        self.assertEquals(self.plugin.authenticate(make_environ(), {}), None)
