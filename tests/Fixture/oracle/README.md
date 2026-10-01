# The OpenSSL oracle of the sender

The OpenSSL command line, a verifier that is no SAML library, verifies the detached signature of every signed URL
`RedirectSender` writes, and Python's zlib, a decoder of raw DEFLATE that is not PHP's, inflates its message (section
9.1 of `spec/bindings.md`). Nothing of the package, of `xml-security` or of PHP takes part in the verification: the
octets are built again from the URL, by name, whatever the order of its parameters, as SAML Bindings §3.4.4.1 says,
and the message must inflate to the very document the model's writer wrote for it, unsigned and serialized once.

`tests/Unit/RedirectSenderOracleTest.php` writes, into the directory `REDIRECT_ORACLE` names, a signed URL for an
`AuthnRequest` of the service provider, a `LogoutRequest` of the identity provider and a `LogoutResponse` of the
service provider, under every algorithm the build has (RSA with SHA-256, SHA-384 and SHA-512, and their RSASSA-PSS
forms on PHP 8.5 with OpenSSL 3.1), each without `RelayState` and with one of 80 bytes, plus an `AuthnRequest` to a
`Destination` holding its own query: `<signer>-<message>-<algorithm>[-relay-state].url`, each next to the document
its message must inflate to, the same name ending in `.xml`. A PSS signature is random, so nothing here is pinned: the
URLs are written again on every run, 37 of them on PHP 8.5, 19 on PHP 8.4.

- `read-redirect-url.py` reads one URL with Python alone: the query after the first `?`, split on `&` and each segment
  on its first `=`; the octets `SAMLRequest=` or `SAMLResponse=` and its raw value, then `&RelayState=` and its raw
  value when present, then `&SigAlg=` and its raw value, still percent-encoded; `Signature` and the message
  percent-decoded by `urllib.parse.unquote_to_bytes()`, base64-decoded by `base64.b64decode(..., validate=True)`; the
  message inflated by `zlib.decompressobj(-15)`, raw DEFLATE, the stream complete and nothing after it.
- `verify-redirect.sh` runs it on each URL it is given, then OpenSSL over the octets under the certificate it is given,
  and `cmp` between the inflated message and the `.xml` next to the URL; it fails on the first URL that does not hold.

The job Oracle of the CI writes the URLs in the phpqa image of PHP 8.5 and verifies them in Alpine 3.22. On the
developer's machine:

```
PHP_VERSION=8.5 castor redirect-oracle   # writes into tmp-phpqa/redirect-oracle, which git ignores, then verifies each
```

which runs, in `alpine:3.22` with `apk add openssl python3`, the repository mounted read-only:

```
sh tests/Fixture/oracle/verify-redirect.sh tests/Fixture/keys/sp-signing-certificate.pem tmp-phpqa/redirect-oracle/sp-*.url
sh tests/Fixture/oracle/verify-redirect.sh tests/Fixture/keys/idp-signing-certificate.pem tmp-phpqa/redirect-oracle/idp-*.url
```

and, for each URL, with `public.pem` from `openssl x509 -in <certificate> -pubkey -noout`:

```
python3 tests/Fixture/oracle/read-redirect-url.py <file.url> <directory>
openssl dgst -sha256 -verify public.pem -signature signature octets                    # RSA-SHA256
openssl dgst -sha384 -verify public.pem -signature signature octets                    # RSA-SHA384
openssl dgst -sha512 -verify public.pem -signature signature octets                    # RSA-SHA512
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sigopt rsa_mgf1_md:sha256 -verify public.pem -signature signature octets          # RSASSA-PSS with SHA-256
openssl dgst -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sigopt rsa_mgf1_md:sha384 -verify public.pem -signature signature octets          # RSASSA-PSS with SHA-384
openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sigopt rsa_mgf1_md:sha512 -verify public.pem -signature signature octets          # RSASSA-PSS with SHA-512
cmp message.xml <file.xml>
```

the `openssl dgst` line chosen by the URI `SigAlg` names. `rsa_pss_saltlen:digest` verifies a salt of exactly the
digest's length, which RFC 6931 §2.3 requires of these URIs and which OpenSSL 3.1 and later produce by default.

Measured on 1 October 2026, `castor redirect-oracle` on PHP 8.5.10 (OpenSSL 3.5.7 in the phpqa image), verified in
Alpine 3.22 with OpenSSL 3.5.9 and Python 3.12.14: the 37 URLs verified, the PSS ones under
`rsa_pss_saltlen:digest`. The same scripts refuse a URL whose `RelayState` was changed after signing (OpenSSL's
`Verification failure`), a document that differs by one byte from the inflated message (`cmp`), and a URL verified
under the other party's certificate.
