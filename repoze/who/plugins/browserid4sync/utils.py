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

import threading
import heapq


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


class NonceCache(object):
    """Object for managing a short-lived cache of nonce values.

    This class allow easy management of client-generated nonces.  It keeps
    a set of seen nonce values so that they can be looked up quickly, and
    a queue ordering them by timestamp so that they can be purged when
    they expire.
    """

    def __init__(self, timeout=None):
        if timeout is None:
            timeout = 5 * 60
        self.timeout = timeout
        self.nonces = set()
        self.purge_lock = threading.Lock()
        self.purge_queue = []

    def __contains__(self, nonce):
        """Check if the given nonce is in the cache."""
        return (nonce in self.nonces)

    def add(self, nonce, timestamp):
        """Add the given nonce to the cache."""
        with self.purge_lock:
            # Purge a few expired nonces to make room.
            # Don't purge *all* of them, since we don't want to pause too long.
            purge_deadline = time.time() - self.timeout
            try:
                for _ in xrange(5):
                    (old_timestamp, old_nonce) = self.purge_queue[0]
                    if old_timestamp >= purge_deadline:
                        break
                    self.nonces.remove(old_nonce)
                    heapq.heappop(self.purge_queue)
            except (IndexError, KeyError):
                pass
            # Add the new nonce into queue and map.
            heapq.heappush(self.purge_queue, (timestamp, nonce))
            self.nonces.add(nonce)
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
# The Original Code is Sauropod.
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

Helper functions for minimal sauropod server.

"""

import re
import json
import urllib2


# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
_AUTH_PARAM_RE = re.compile(r"^\s*" + _AUTH_PARAM_RE + r"\s*$")

# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")


def parse_authz_header(request, *default):
    """Parse the authorization header into an identity dict.

    This function can be used to extract the Authorization header from a
    request and parse it into a dict of its constituent parameters.  The
    auth scheme name will be included under the key "scheme", and any other
    auth params will appear as keys in the dictionary.

    For example, given the following auth header value:

        'Digest realm="Sync" userame=user1 response="123456"'

    This function will return the following dict:

        {"scheme": "Digest", realm: "Sync",
         "username": "user1", "response": "123456"}

    """
    # Grab the auth header from the request, if any.
    authz = request.environ.get("HTTP_AUTHORIZATION")
    if authz is None:
        if default:
            return default[0]
        raise ValueError("Missing auth parameters")
    scheme, kvpairs_str = authz.split(None, 1)
    # Split the parameters string into individual key=value pairs.
    # In the simple case we can just split by commas to get each pair.
    # Unfortunately this will break if one of the values contains a comma.
    # So if we find a component that isn't a well-formed key=value pair,
    # then we stitch bits back onto the end of it until it is.
    kvpairs = []
    if kvpairs_str:
        for kvpair in kvpairs_str.split(","):
            if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                kvpairs.append(kvpair)
            else:
                kvpairs[-1] = kvpairs[-1] + "," + kvpair
        if not _AUTH_PARAM_RE.match(kvpairs[-1]):
            if default:
                return default[0]
            raise ValueError('Malformed auth parameters')
    # Now we can just split by the equal-sign to get each key and value.
    params = {"scheme": scheme}
    for kvpair in kvpairs:
        (key, value) = kvpair.strip().split("=", 1)
        # For quoted strings, remove quotes and backslash-escapes.
        if value.startswith('"'):
            value = value[1:-1]
            if _UNESC_QUOTE_RE.search(value):
                if default:
                    return default[0]
                raise ValueError("Unescaped quote in quoted-string")
            value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
        params[key] = value
    return params
