# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest2
import time
import json
import base64

from webob import Request

from repoze.who.plugins.vepauth.utils import (strings_differ,
                                              NonceCache,
                                              parse_authz_header,
                                              sign_request,
                                              get_signature_base_string)


class TestUtils(unittest2.TestCase):

    def test_strings_differ(self):
        # We can't really test the timing-invariance, but
        # we can test that we actually compute equality!
        self.assertTrue(strings_differ("", "a"))
        self.assertTrue(strings_differ("b", "a"))
        self.assertTrue(strings_differ("cc", "a"))
        self.assertTrue(strings_differ("cc", "aa"))
        self.assertFalse(strings_differ("", ""))
        self.assertFalse(strings_differ("D", "D"))
        self.assertFalse(strings_differ("EEE", "EEE"))

    def test_nonce_cache(self):
        # The default timeout should be 5 minutes.
        cache = NonceCache()
        self.assertEquals(cache.timeout, 5 * 60)
        # The cache should be empty to start with.
        timeout = 0.1
        cache = NonceCache(timeout=timeout)
        self.assertEquals(cache.timeout, 0.1)
        self.assertEquals(len(cache), 0)
        self.assertFalse("abc" in cache)
        # After adding a nonce, it should contain just that item.
        cache.add("abc", time.time())
        self.assertEquals(len(cache), 1)
        self.assertTrue("abc" in cache)
        self.assertFalse("def" in cache)
        # After the timeout passes, the item should be expired.
        time.sleep(timeout)
        self.assertFalse("abc" in cache)
        # Writing to the cache purges expired nonces but keeps valid ones.
        cache.add("abc", time.time())
        time.sleep(timeout/2)
        cache.add("def", time.time())
        self.assertTrue("abc" in cache)
        self.assertTrue("def" in cache)
        self.assertFalse("xyz" in cache)
        time.sleep(timeout/2)
        cache.add("xyz", time.time())
        self.assertFalse("abc" in cache)
        self.assertTrue("def" in cache)
        self.assertTrue("xyz" in cache)
        self.assertEquals(len(cache), 2)

    def test_parse_authz_header(self):
        def req(authz):
            """Make a fake request with the given authz header."""
            class request:
                environ = {"HTTP_AUTHORIZATION": authz}
            return request

        # Test parsing of a single unquoted parameter.
        params = parse_authz_header(req('Digest realm=hello'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['realm'], 'hello')

        # Test parsing of multiple parameters with mixed quotes.
        params = parse_authz_header(req('Digest test=one, again="two"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], 'one')
        self.assertEquals(params['again'], 'two')

        # Test parsing of an escaped quote and empty string.
        params = parse_authz_header(req('Digest test="\\"",again=""'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['test'], '"')
        self.assertEquals(params['again'], '')

        # Test parsing of embedded commas, escaped and non-escaped.
        params = parse_authz_header(req('Digest one="1\\,2", two="3,4"'))
        self.assertEquals(params['scheme'], 'Digest')
        self.assertEquals(params['one'], '1,2')
        self.assertEquals(params['two'], '3,4')

        # Test parsing on various malformed inputs
        self.assertRaises(ValueError, parse_authz_header, req(None))
        self.assertRaises(ValueError, parse_authz_header, req(""))
        self.assertRaises(ValueError, parse_authz_header, req(" "))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken raw-token'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unclosed-quote'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm=unopened-quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="unescaped"quote"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="escaped-end-quote\\"'))
        self.assertRaises(ValueError, parse_authz_header,
                          req('Broken realm="duplicated",,what=comma'))

        # Test all those again, but returning a default value
        self.assertEquals(None, parse_authz_header(req(None), None))
        self.assertEquals(None, parse_authz_header(req(""), None))
        self.assertEquals(None, parse_authz_header(req(" "), None))
        self.assertEquals(None,
                          parse_authz_header(req('Broken raw-token'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unclosed-quote'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm=unopened-quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="unescaped"quote"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="escaped-end-quote\\"'), None))
        self.assertEquals(None, parse_authz_header(
                          req('Broken realm="duplicated",,what=comma'), None))

    def test_signature_base_string(self):
        # This is the example used in Section 3.4.1.1 of RFC-5849.
        req = ""\
            'POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1\r\n'\
            'Host: example.com\r\n'\
            'Content-Type: application/x-www-form-urlencoded\r\n'\
            'Authorization: OAuth realm="Example", '\
                         'oauth_consumer_key="9djdj82h48djs9d2", '\
                         'oauth_token="kkk9d7dh3k39sjv7", '\
                         'oauth_signature_method="HMAC-SHA1", '\
                         'oauth_timestamp="137131201", '\
                         'oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D", '\
                         'oauth_nonce="7d8f3e4a"\r\n'\
            '\r\n'\
            'c2&a3=2+q'
        sigstr = 'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a'\
                 '3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c'\
                 '2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_non'\
                 'ce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oau'\
                 'th_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7'
        # IanB, *thank you* for Request.from_string!
        mysigstr = get_signature_base_string(Request.from_string(req))
        self.assertEquals(sigstr, mysigstr)

    def test_sign_request_throws_away_other_auth_params(self):
        req = Request.blank("/")
        req.authorization = ("Digest", {"response": "helloworld"})
        sign_request(req, "token", "secret")
        self.assertEquals(req.authorization[0], "OAuth")
