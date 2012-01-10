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

from zope.interface.verify import verifyClass

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger

import vep
from vep.utils import get_assertion_info

from repoze.who.plugins.vepauth import VEPAuthPlugin, make_plugin
from repoze.who.plugins.vepauth.tokenmanager import SignedTokenManager


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


class DummyVerifierValid(object):
    """Dummy verifier class that thinks everything is valid."""

    def verify(self, assertion, audience=None):
        info = get_assertion_info(assertion)
        return {"status": "okay",
                "audience": info["audience"],
                "email": info["principal"]["email"]}


class DummyVerifierInvalid(object):
    """Dummy verifier class that thinks everything is invalid."""

    def verify(self, assertion, audience=None):
        raise ValueError("Invalid BrowserID assertion")


class TestVEPAuthPlugin(unittest2.TestCase):
    """Testcases for the main VEPAuthPlugin class."""

    def test_implements(self):
        verifyClass(IIdentifier, VEPAuthPlugin)
        verifyClass(IAuthenticator, VEPAuthPlugin)
        verifyClass(IChallenger, VEPAuthPlugin)

    def test_make_plugin(self):
        # Test that everything can be set explicitly.
        def ref(name):
            return "repoze.who.plugins.browserid.tests.test_plugin:" + name
        plugin = make_plugin(
            audiences="example.com",
            token_url="/test_token_url",
            verifier="repoze.who.plugins.vepauth.tests.test_plugin:DummyVerifierValid",
            token_manager="repoze.who.plugins.vepauth.tests.test_plugin:DummyVerifierInvalid",
            nonce_timeout=42)
        self.assertEquals(plugin.audiences, ["example.com"])
        self.assertEquals(plugin.token_url, "/test_token_url")
        self.assertTrue(isinstance(plugin.verifier, DummyVerifierValid))
        self.assertTrue(isinstance(plugin.token_manager, DummyVerifierInvalid))
        self.assertEquals(plugin.nonce_timeout, 42)
        # TODO: check setting of urlopen from a dotted-name string.
        # est that everything gets a sensible default.
        self.assertRaises(ValueError, make_plugin)
        plugin = make_plugin("one two")
        self.assertEquals(plugin.audiences, ["one", "two"])
        self.assertEquals(plugin.token_url, "/request_token")
        self.assertTrue(isinstance(plugin.verifier, vep.RemoteVerifier))
        self.assertTrue(isinstance(plugin.token_manager, SignedTokenManager))
        self.assertEquals(plugin.nonce_timeout, 5 * 60)
