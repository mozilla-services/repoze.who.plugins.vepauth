# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Helper functions for repoze.who.plugins.vepauth.

"""

import os
import re
import time
import heapq
import urllib
import threading
import hmac
from hashlib import sha1
from base64 import b64encode


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
    # This outer try-except catches ValueError and
    # turns it into return-default if necessary.
    try:
        # Grab the auth header from the request, if any.
        authz = request.environ.get("HTTP_AUTHORIZATION")
        if authz is None:
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
                raise ValueError('Malformed auth parameters')
        # Now we can just split by the equal-sign to get each key and value.
        params = {"scheme": scheme}
        for kvpair in kvpairs:
            (key, value) = kvpair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if _UNESC_QUOTE_RE.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
            params[key] = value
        return params
    except ValueError:
        if default:
            return default[0]
        raise


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
        self.nonce_timestamps = {}
        self.purge_lock = threading.Lock()
        self.purge_queue = []

    def __contains__(self, nonce):
        """Check if the given nonce is in the cache."""
        timestamp = self.nonce_timestamps.get(nonce)
        if timestamp is None:
            return False
        if timestamp + self.timeout < time.time():
            return False
        return True

    def __len__(self):
        """Get the number of items currently in the cache."""
        return len(self.nonce_timestamps)

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
                    heapq.heappop(self.purge_queue)
                    del self.nonce_timestamps[old_nonce]
            except (IndexError, KeyError):
                pass
            # Add the new nonce into both queue and map.
            heapq.heappush(self.purge_queue, (timestamp, nonce))
            self.nonce_timestamps[nonce] = timestamp


def sign_request(request, oauth_consumer_key, oauth_consumer_secret):
    """Sign the given request using Two-Legged OAuth.

    This function implements the client-side request signing algorithm as
    expected by the server, i.e. Two-Legged OAuth as described in Section 3
    of RFC 5849.

    It's not used by the repoze.who plugin itself, but is handy for testing
    purposes and possibly for python client libraries.
    """
    if isinstance(oauth_consumer_key, unicode):
        oauth_consumer_key = oauth_consumer_key.encode("ascii")
    if isinstance(oauth_consumer_secret, unicode):
        oauth_consumer_secret = oauth_consumer_secret.encode("ascii")
    # Use OAuth params from the request if present.
    # Otherwise generate some fresh ones.
    params = parse_authz_header(request, {})
    if params and params.pop("scheme") != "OAuth":
        params.clear()
    params["oauth_consumer_key"] = oauth_consumer_key
    params["oauth_signature_method"] = "HMAC-SHA1"
    params["oauth_version"] = "1.0"
    if "oauth_timestamp" not in params:
        params["oauth_timestamp"] = str(int(time.time()))
    if "oauth_nonce" not in params:
        params["oauth_nonce"] = os.urandom(5).encode("hex")
    # Calculate the signature and add it to the parameters.
    sigstr = get_signature_base_string(request, params)
    params["oauth_signature"] = get_signature(sigstr, oauth_consumer_secret)
    # Serialize the parameters back into the authz header.
    # WebOb has logic to do this that's not perfect, but good enough for us.
    request.authorization = ("OAuth", params)


def get_signature(sigdata, secret):
    """Get the OAuth signature for the given data, using the given secret.

    This is straight from Section 3.4 of RFC-5849, using the HMAC-SHA1
    signature method.
    """
    key = encode_oauth_parameter(secret) + "&"
    return b64encode(hmac.new(key, sigdata, sha1).digest())


def get_signature_base_string(request, authz=None):
    """Get the base string to be signed for OAuth authentication.

    This method takes a WebOb Request object and returns the data that
    should be signed for OAuth authentication of that request, a.k.a the
    "signature base string" as defined in section 3.4.1 of RFC-5849.

    If the "authz" parameter is not None, it is assumed to be a pre-parsed
    dict of parameters from the Authorization header.  If it is missing or
    None then the Authorization header from the request will be parsed
    directly.  This should only be used as an optimisation to avoid double
    parsing of the header.
    """
    # The signature base string contains three main components,
    # percent-encoded and separated by an ampersand.
    bits = [] 
    # 1) The request method in upper-case.
    bits.append(request.method.upper())
    # 2) The base string URI.
    # Fortunately WebOb's request.path_url gets us most of the way there.
    # We just need to twiddle the scheme and host part to be in lowercase.
    uri = request.path_url
    host_len = len(request.host_url)
    uri = uri[:host_len].lower() + uri[host_len:]
    bits.append(uri)
    # 3) The request parameters.
    # Parameters can come from GET vars, POST vars, or the Authz header.
    # We assume that WebOb has already put them in their decoded form.
    params = request.GET.items()
    if request.content_type == "application/x-www-form-urlencoded":
        params.extend(request.POST.items())
    if authz is None:
        authz = parse_authz_header(request, {})
    for item in authz.iteritems():
        if item[0] not in ("scheme", "realm", "oauth_signature"):
            params.append(item)
    params = [(encode_oauth_parameter(k), encode_oauth_parameter(v))
              for k, v in params]
    params.sort()
    bits.append("&".join("%s=%s" % (k, v) for k, v in params))
    # Jow encode and join together the the components.
    # Yes, this double-encodes the parameters.
    # That's what the spec requires.
    return "&".join(encode_oauth_parameter(bit) for bit in bits)


def encode_oauth_parameter(value):
    """Percent-encode an oauth parameter name or value.

    This encapsulates the fiddly definitions from Section 3.6 of RFC-5849,
    to produce a consistent canonical escaped form for any string.
    """
    if isinstance(value, unicode):
        value = value.encode("utf8")
    return urllib.quote(value, safe="-._~")


def decode_oauth_parameter(value):
    """Percent-decode an oauth parameter name or value.

    This encapsulates the fiddly definitions from Section 3.6 of RFC-5849,
    to decode from the  consistent canonical escaped form of any string.
    """
    return urllib.unquote(value)
