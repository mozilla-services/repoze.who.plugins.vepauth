==========================
repoze.who.plugins.vepauth
==========================

This is a repoze.who plugin for automated authentication via BrowserID:

    https://browserid.org/
    https://wiki.mozilla.org/Identity/BrowserIDSync

The plugin implements an experimental protocol for authenticating to ReSTful
web services with the Verified Email Protocol, a.k.a Mozilla's BrowserID
project.  It is designed for use in automated tools like the Firefox Sync
Client.  If you're looking for something to use for human visitors on your
site, please try:

    http://github.com/mozilla-services/repoze.who.plugins.browserid

When accessing a protected resource, the server will generate a 401 challenge
response with the scheme "OAuth+VEP" as follows::

    > GET /protected_resource HTTP/1.1
    > Host: example.com

    < HTTP/1.1 401 Unauthorized
    < WWW-Authenticate: OAuth+VEP url="/request_token"

The client should extract the url from this challenge and POST a VEP assertion
to that location.  This will create a new authentication session and return a
set of OAuth client credentials::

    > POST /request_token HTTP/1.1
    > Host: example.com
    > Content-Type: application/x-www-form-urlencoded
    >
    > assertion=VEP_ASSERTION_DATA

    < HTTP/1.1 200 OK
    < Content-Type: application/json
    <
    < {
    <   "oauth_consumer_key": SESSION_TOKEN,
    <   "oauth_consumer_secret": SESSION_SECRET
    < }

Subsequent requests should be signed using these credentials in Two-Legged
OAuth mode::

    > GET /protected_resource HTTP/1.1
    > Host: example.com
    > Authorization: OAuth oauth_consumer_key=SESSION_TOKEN,
    >                      oauth_signature_method="HMAC-SHA1",
    >                      oauth_version="1.0",
    >                      oauth_timestamp=TIMESTAMP,
    >                      oauth_nonce=NONCE
    >                      oauth_signature=SIGNATURE

    < HTTP/1.1 200 OK
    < Content-Type: text/plain
    <
    < For your eyes only:  secret data!

Session tokens are timestamped and will eventually expire.  If this happens
you will receive a 401 response as before, and should POST a new assertion
to obtain fresh credentials.

Extending the token management
------------------------------

`repoze.who.plugins.vepauth` is extensible. If you want to provide a different
mechanism to manage the tokens, you can do so by providing a different token
manager instance to the plugin with the `token_manager` option.

The `TokenManager` class have two methods than need to be implemented (it's an
abstract class): `make_token` and `parse_token`. The implementation details are
left to the childs classes.

`repose.who.plugins.vepauth` comes with one `SignedTokenManager` which
implement a simple token management class in pure python. It has a number of
methods that can be overridden to customize its behavior.
