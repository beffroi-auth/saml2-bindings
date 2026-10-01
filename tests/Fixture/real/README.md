# Real query strings and metadata

Section 9.4 of `spec/bindings.md`: what real implementations sent, bytes as received, named with their origin and the
date of their capture, verified and validated by `tests/Unit/RealDocumentsTest.php` with a clock frozen at the capture.
The identities are disposable: the keys are the test keys of `tests/Fixture/keys/`, and the hosts are `localhost`.

## SimpleSAMLphp 2.5.3.1, 30 September 2026

Captured by the harness of `beffroi-php/saml2-model` (its `tests/Interop/simplesamlphp/`, section 4 of its README), in
the exchange between SimpleSAMLphp's service provider `for-model` and the model's identity provider, run with
`castor simplesamlphp --keep` on PHP 8.5.10 at 13:07 UTC, its documents issued between 13:07:34 and 13:07:35 UTC.
Committed to the model by c2fa7dd (30 September 2026), and copied here byte for byte from its `tests/Fixture/real/` at
commit 9c833c5 of its `main` (1 October 2026), the merge of its stack.

| File | What | Bytes |
|---|---|---|
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt` | the query string of `for-model`'s `AuthnRequest` to `http://localhost:8083/model/idp/sso`: `SAMLRequest`, `RelayState`, `SigAlg` (RSA-SHA256), `Signature`, in that order, signed under `sign.authnrequest`, no final line feed | 952 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt` | the query string of `for-model`'s `LogoutRequest` to `http://localhost:8083/model/idp/slo`, the same four parameters, signed under `sign.logout`, no final line feed | 1 073 |
| `simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml` | `for-model`'s metadata as it was served, `AuthnRequestsSigned="true"`, the certificate whose key verifies both query strings | 4 384 |

The XML each query string carries is the model's evidence, kept under its own `tests/Fixture/real/`
(`simplesamlphp-2.5.3.1-sp-authnrequest-to-model-2026-09-30.xml`, `...-sp-logoutrequest-to-model-2026-09-30.xml`); the
query string as it arrived is this package's.
