# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Helper functions for repoze.who.plugins.vepauth.

"""

import os
import re
import time
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


def sign_request(request, token, secret):
    """Sign the given request using MAC access authentication.

    This function implements the client-side request signing algorithm as
    expected by the server, i.e. MAC access authentication as defined by
    RFC-TODO.

    It's not used by the repoze.who plugin itself, but is handy for testing
    purposes and possibly for python client libraries.
    """
    if isinstance(token, unicode):
        token = token.encode("ascii")
    if isinstance(secret, unicode):
        secret = secret.encode("ascii")
    # Use MAC parameters from the request if present.
    # Otherwise generate some fresh ones.
    params = parse_authz_header(request, {})
    if params and params.pop("scheme") != "MAC":
        params.clear()
    params["id"] = token
    if "ts" not in params:
        params["ts"] = str(int(time.time()))
    if "nonce" not in params:
        params["nonce"] = os.urandom(5).encode("hex")
    # Calculate the signature and add it to the parameters.
    params["mac"] = get_mac_signature(request, secret, params)
    # Serialize the parameters back into the authz header.
    # WebOb has logic to do this that's not perfect, but good enough for us.
    request.authorization = ("MAC", params)


def get_mac_signature(request, secret, params=None):
    """Get the MAC signature for the given data, using the given secret."""
    if params is None:
        params = parse_authz_header(request, {})
    sigstr = get_normalized_request_string(request, params)
    return b64encode(hmac.new(secret, sigstr, sha1).digest())


def get_normalized_request_string(request, params=None):
    """Get the string to be signed for MAC access authentication.

    This method takes a WebOb Request object and returns the data that
    should be signed for MAC access authentication of that request, a.k.a
    the "normalized request string" as defined in section 3.2.1 of RFC-TODO.

    If the "params" parameter is not None, it is assumed to be a pre-parsed
    dict of MAC parameters as one might find in the Authorization header.  If
    it is missing or  None then the Authorization header from the request will
    be parsed to determine the necessary parameters.
    """
    if params is None:
        params = parse_authz_header(request, {})
    bits = []
    bits.append(params["ts"])
    bits.append(params["nonce"])
    bits.append(request.method.upper())
    bits.append(request.path_qs)
    try:
        host, port = request.host.rsplit(":", 1)
    except ValueError:
        host = request.host
        if request.scheme == "http":
            port = "80"
        elif request.scheme == "https":
            port = "443"
        else:
            msg = "Unknown scheme %r has no default port" % (request.scheme,)
            raise ValueError(msg)
    bits.append(host.lower())
    bits.append(port)
    bits.append(params.get("ext", ""))
    bits.append("") # to get the trailing newline
    return "\n".join(bits)


def check_mac_signature(request, secret, params=None):
    """Check that the request is correctly signed with the given secret."""
    if params is None:
        params = parse_authz_header(request, {})
    # Any KeyError here indicates a missing parameter,
    # which implies an invalid signature.
    try:
        expected_sig = get_mac_signature(request, secret, params)
        return not strings_differ(params["mac"], expected_sig)
    except KeyError:
        return False
