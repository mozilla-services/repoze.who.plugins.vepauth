# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import time
import math
import json
import hmac
import hashlib
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode

from repoze.who.plugins.vepauth.utils import strings_differ


class TokenManager(object):
    """Interface definition for management of OAuth tokens.

    This class defines the necessary methods for managing tokens as part
    of 2-legged OAuth signing:

        * make_token:     create a new (token, secret) pair
        * parse_token:    extract (data, secret) from a given token

    Token management is split out into a separate class to make it easy
    to adjust the various time-vs-memory-security tradeoffs involved -
    for example, you might provide a custom TokenManager that stores its
    state in memcache so it can be shared by several servers.
    """

    def make_token(self, data):
        """Generate a new token value.

        This method generates a new token associated with the given VEP data,
        along with a secret key used for signing requests.  These will both
        be unique and non-forgable and contain only characters from the
        urlsafe base64 alphabet.
        """
        raise NotImplementedError  # pragma: no cover

    def parse_token(self, token):
        """Get the data and secret associated with the given token.

        If the given token is valid then this method returns its user data
        dict and the associated secret key.  If the token is invalid (e.g.
        it is expired) then this method raises ValueError.
        """
        raise NotImplementedError  # pragma: no cover


class SignedTokenManager(object):
    """Class managing signed OAuth tokens.

    This class provides a TokenManager implementation based on signed
    timestamped tokens.  It should provide a good balance between speed,
    memory-usage and security for most applications.

    The token contains an embedded (unencrypted!) userid and timestamp.
    The secret key is derived from the token using HKDF.

    The following options customize the use of this class:

       * secret:  string key used for signing the token;
                  if not specified then a random bytestring is used.

       * timeout: the time after which a token will expire.

       * hashmod:  the hashing module to use for various HMAC operations;
                   if not specified then hashlib.sha1 will be used.
    """

    def __init__(self, secret=None, timeout=None, hashmod=None):
        # Default hashmod is SHA1
        if hashmod is None:
            hashmod = hashlib.sha1
        elif isinstance(hashmod, basestring):
            hashmod = getattr(hashlib, hashmod)
        digest_size = hashmod().digest_size
        # Default secret is a random bytestring.
        if secret is None:
            secret = os.urandom(digest_size)
        # Default timeout is five minutes.
        if timeout is None:
            timeout = 5 * 60
        # The configured secret *should* be a uniformly random bytestring,
        # but you never know what whacky ideas people will come up with.
        # Applying the "extract" step can't hurt and might just help security.
        self.secret = HKDF_extract("vepauth", secret)
        self.timeout = timeout
        self.hashmod = hashmod
        self.hashmod_digest_size = digest_size
        # We use HMAC for two different purposes: signing tokens and
        # generating secret keys.  It seems prudent to use a different
        # key for each purpose.
        okm = HKDF_expand(self.secret, "", digest_size * 2)
        self._signing_key = okm[:digest_size]
        self._token_key = okm[digest_size:]

    def make_token(self, data):
        """Generate a new token for the given userid.

        In this implementation the token is a JSON dump of the given data,
        including an expiry time and salt.  It has a HMAC signature appended
        and is b64-encoded for transmission.
        """
        data = data.copy()
        data["salt"] = os.urandom(3).encode("hex")
        data["expires"] = time.time() + self.timeout
        payload = json.dumps(data)
        sig = self._get_signature(payload)
        assert len(sig) == self.hashmod_digest_size
        token = b64encode(payload + sig)
        return token, self._get_secret(token)

    def parse_token(self, token):
        """Extract the data and secret key from the token, if valid.

        In this implementation the token is valid is if has a valid signature
        and if the embedded expiry time has not passed.
        """
        # Parse the payload and signature from the token.
        try:
            decoded_token = b64decode(token)
        except TypeError, e:
            raise ValueError(str(e))
        payload = decoded_token[:-self.hashmod_digest_size]
        sig = decoded_token[-self.hashmod_digest_size:]
        # Carefully check the signature.
        # This is a deliberately slow string-compare to avoid timing attacks.
        # Read the docstring of strings_differ for more details.
        expected_sig = self._get_signature(payload)
        if strings_differ(sig, expected_sig):
            raise ValueError("token has invalid signature")
        # Only decode *after* we've confirmed the signature.
        data = json.loads(payload)
        # Check whether it has expired.
        if data["expires"] <= time.time():
            raise ValueError("token has expired")
        # Find something we can use as repoze.who.userid.
        if "repoze.who.userid" not in data:
            for key in ("username", "userid", "uid", "email"):
                if key in data:
                    data["repoze.who.userid"] = data[key]
                    break
            else:
                raise ValueError("token contains no userid")
        # Re-generate the secret key and return.
        return data, self._get_secret(token)

    def _get_secret(self, token):
        """Get the secret key associated with the given token.

        In this implementation we generate the secret key using HKDF-Expand
        with the token as the "info" parameter.  This avoids having to keep
        any extra state in memory while being sufficiently unguessable.
        """
        secret = HKDF_expand(self._token_key, token, self.hashmod_digest_size)
        return b64encode(secret)

    def _get_signature(self, value):
        """Calculate the HMAC signature for the given value."""
        return hmac.new(self._signing_key, value, self.hashmod).digest()


def HKDF_extract(salt, IKM, hashmod=hashlib.sha1):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = "\x00" * hashmod().digest_size
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha1):
    """HKDF-Expand; see RFC-5869 for the details."""
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = ""
    output = []
    for i in xrange(1, N + 1):
        data = T + info + chr(i)
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return "".join(output)[:L]
