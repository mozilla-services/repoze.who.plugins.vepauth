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
import hashlib
import time

from repoze.who.plugins.vepauth.tokenmanager import (SignedTokenManager,
                                                     HKDF_extract,
                                                     HKDF_expand)


class TestTokens(unittest2.TestCase):

    def test_token_validation(self):
        manager = SignedTokenManager(timeout=0.2)
        token, secret = manager.make_token({"email":"tester"})
        # Proper token == valid.
        data, secret2 = manager.parse_token(token)
        self.assertEquals(data["repoze.who.userid"], "tester")
        self.assertEquals(secret, secret2)
        # Bad signature == not valid.
        bad_token = token[:-1] + ("X" if token[-1] == "Z" else "Z")
        self.assertRaises(ValueError, manager.parse_token, bad_token)
        # Modified payload == not valid.
        bad_token = "admin" + token[6:]
        self.assertRaises(ValueError, manager.parse_token, bad_token)
        # Expired token == not valid.
        time.sleep(0.2)
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
