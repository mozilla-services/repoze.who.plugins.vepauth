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

Helper functions for repoze.who.plugins.browserid4sync.

"""

import vep.utils


# TODO: this function itself could probably live in vep.utils.

def parse_assertion(assertion):
    """Parse interesting information out of a BrowserID assertion.

    This function decodes and parses the given BrowserID assertion, returning
    a dict with the following items:

       * principal:  the asserted identity, eg: {"email": "test@example.com"}
       * audience:   the audience to whom it is asserted

    This does *not* verify the assertion at all, it is merely a way to see
    the information that is being asserted.  If the assertion is malformed
    then ValueError will be raised.
    """
    info = {}
    # Decode the bundled-assertion envelope.
    try:
        data = vep.utils.decode_json_bytes(assertion)
        certificates = data["certificates"]
        assertion = data["assertion"]
        # Get the asserted principal out of the certificate chain.
        info["principal"] = parse_jwt(certificates[0])["principal"]
        # Get the audience out of the assertion token.
        info["audience"] = parse_jwt(assertion)["aud"]
    except (TypeError, KeyError), e:
        raise ValueError(str(e))
    return info


def parse_jwt(token):
    """Parse a JWT to get the contained information.

    This function parses a JSON Web Token and returns the contained dict of
    information.  It does not validate the signature.
    """
    payload = token.split(".")[1]
    return vep.utils.decode_json_bytes(payload)


def strings_differ(string1, string2):
    """Check whether two strings differ while avoiding timing attacks.

    This function returns True if the given strings differ and False
    if they are equal.  It's careful not to leak information about *where*
    they differ as a result of its running time, which can be very important
    to avoid certain timing-related crypto attacks:

        http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf

    """
    if len(string1) != len(string2):
        return True
    invalid_bits = 0
    for a, b in zip(string1, string2):
        invalid_bits += a != b
    return invalid_bits != 0
