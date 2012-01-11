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
import time
import json
import base64

from webob import Request

from repoze.who.plugins.vepauth.utils import (strings_differ,
                                              NonceCache,
                                              parse_authz_header,
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
        timeout = 0.1

        # The cache should be empty to start with.
        cache = NonceCache(timeout=timeout)
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
