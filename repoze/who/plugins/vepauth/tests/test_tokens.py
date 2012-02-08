# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest2
import hashlib
import time

from webob.exc import HTTPNotFound

from repoze.who.plugins.vepauth.tokenmanager import (
    SignedTokenManager,
    HKDF_extract,
    HKDF_expand
)


class FakeRequest(object):
    def __init__(self, matchdict=None):
        self.matchdict = matchdict or {}


class TestTokens(unittest2.TestCase):

    def test_token_validation(self):
        manager = SignedTokenManager(timeout=0.2)
        request = FakeRequest()
        token, secret, _ = manager.make_token(request, {"email": "tester"})
        # Proper token == valid.
        data, secret2 = manager.parse_token(token)
        self.assertEquals(data["repoze.who.userid"], "tester")
        self.assertEquals(secret, secret2)
        # Bad signature == not valid.
        bad_token = token[:-1] + ("X" if token[-1] == "Z" else "Z")
        self.assertRaises(ValueError, manager.parse_token, bad_token)
        bad_token = ("X" * 50).encode("base64").strip()
        self.assertRaises(ValueError, manager.parse_token, bad_token)
        # Modified payload == not valid.
        bad_token = "admin" + token[6:]
        self.assertRaises(ValueError, manager.parse_token, bad_token)
        # Expired token == not valid.
        time.sleep(0.2)
        self.assertRaises(ValueError, manager.parse_token, token)

    def test_multiple_application_are_supported(self):
        apps = ("foo", "bar", "baz")
        manager = SignedTokenManager(timeout=0.2, applications=apps)

        # this should work as we have an application specified
        request = FakeRequest({"application": "foo"})
        token, secret, extra = manager.make_token(request, {"email": "tester"})

        # asking for an unknown application should raise a 404
        request = FakeRequest({"application": "undefined"})
        self.assertRaises(HTTPNotFound, manager.make_token, request,
                          {"email": "tester"})

    def test_specifying_no_applications_works(self):
        manager = SignedTokenManager(timeout=0.2)
        manager.make_token(FakeRequest(), {"email": "tester"})
        # we are not throwing any exception here

    def test_token_dont_validate_without_a_userid(self):
        manager = SignedTokenManager()
        request = FakeRequest()
        token, secret, _ = manager.make_token(request, {"permissions": "all"})
        self.assertRaises(ValueError, manager.parse_token, token)

    def test_loading_hashmod_by_string_name(self):
        manager = SignedTokenManager(hashmod="md5")
        self.assertTrue(manager.hashmod is hashlib.md5)

    def test_hkdf_from_rfc5869_case_1(self):
        hashmod = hashlib.sha256
        ikm = "\x0b" * 22
        salt = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
        info = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"
        L = 42
        PRK = HKDF_extract(salt, ikm, hashmod)
        OKM = HKDF_expand(PRK, info, L, hashmod)
        self.assertEquals(PRK.encode("hex"),
                          "077709362c2e32df0ddc3f0dc47bba6390b6c7"\
                          "3bb50f9c3122ec844ad7c2b3e5")
        self.assertEquals(OKM.encode("hex"),
                          "3cb25f25faacd57a90434f64d0362f2a"\
                          "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"\
                          "34007208d5b887185865")

    def test_hkdf_from_rfc5869_case_7(self):
        hashmod = hashlib.sha1
        ikm = "\x0c" * 22
        salt = None
        info = ""
        L = 42
        PRK = HKDF_extract(salt, ikm, hashmod)
        OKM = HKDF_expand(PRK, info, L, hashmod)
        self.assertEquals(PRK.encode("hex"),
                          "2adccada18779e7c2077ad2eb19d3f3e731385dd")
        self.assertEquals(OKM.encode("hex"),
                          "2c91117204d745f3500d636a62f64f0a"\
                          "b3bae548aa53d423b0d1f27ebba6f5e5"\
                          "673a081d70cce7acfc48")
