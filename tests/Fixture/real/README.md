# Real query strings, forms and metadata

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

## SimpleSAMLphp 2.5.3.1, 1 October 2026

Captured by this package's judge (`tests/Interop/simplesamlphp/`, section 9.5 of the specification), run with
`castor simplesamlphp --keep` on PHP 8.5.10 between 11:03:28 and 11:03:40 UTC, the messages issued between 11:03:33 and
11:03:37 UTC. Each was kept once this package had read it and the model had validated it, or refused it as the table
says. A query string is the raw query of the URL SimpleSAMLphp redirected to, after its `?`, as the consumer reads it
from `QUERY_STRING`; a form is the `application/x-www-form-urlencoded` body a browser posts from the form of the page,
its fields read by the harness's reader of HTML (Dom\HTMLDocument) and encoded as a browser encodes them, what the
consumer's parser then decodes (section 6.8). No final line feed in either.

`capture.php`: SimpleSAMLphp's service provider `default-sp` and its identity provider, as the installation configures
them.

| File | What | Bytes |
|---|---|---|
| `simplesamlphp-2.5.3.1-idp-metadata-2026-10-01.xml` | the identity provider's metadata as served, HTTP-Redirect alone for its single sign-on and single logout services (its default publication) | 3 813 |
| `simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml` | `default-sp`'s metadata as served, `AuthnRequestsSigned="true"` | 4 212 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-query-2026-10-01.txt` | `default-sp`'s `AuthnRequest`, signed under `sign.authnrequest`, its `RelayState` its `ReturnTo` of 56 bytes | 986 |
| `simplesamlphp-2.5.3.1-idp-response-form-2026-10-01.txt` | the response to it, the response and its assertion signed (`saml20.sign.response`, its default), `RelayState` echoed | 9 781 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-query-2026-10-01.txt` | `default-sp`'s `LogoutRequest`, signed under `sign.logout`, its `RelayState` an ID of its state, 43 bytes | 1 061 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-unsigned-refused-query-2026-10-01.txt` | the identity provider's `LogoutResponse` under its defaults, unsigned: read, then refused by the model (`SignatureRequired`, M-2) | 522 |

`exchange.php`: SimpleSAMLphp's two parties and this package's roles at `http://localhost:8093/bindings/`, whose
metadata the exchange wrote with the test keys of `tests/Fixture/keys/` (`RealDocumentsTest` builds the same roles).

| File | What | Bytes |
|---|---|---|
| `simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml` | `for-bindings`'s metadata as served, `AuthnRequestsSigned="true"` | 4 222 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt` | `for-bindings`'s `AuthnRequest` to this package's identity provider, signed, its `ReturnTo` of 44 bytes as `RelayState` | 978 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-long-relaystate-refused-query-2026-10-01.txt` | the same for a `ReturnTo` of 105 bytes, sent as a `RelayState` of 105 bytes: refused by the receiver (`InvalidRelayState`, B-9, SAML Bindings §3.4.3) | 1 041 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-bindings-query-2026-10-01.txt` | `for-bindings`'s `LogoutRequest` to this package's identity provider, signed | 1 053 |
| `simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt` | the identity provider's response to this package's service provider `sp`, both signed, its `RelayState` `bindings login ~` echoed | 9 519 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-query-2026-10-01.txt` | its `LogoutResponse` to `sp`, signed under `sign.logout`, its `RelayState` `bindings logout ~` escaped `bindings+logout+%7E` by PHP's `urlencode()` | 944 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-unsigned-refused-query-2026-10-01.txt` | its `LogoutResponse` to `sp-defaults`, under its defaults, unsigned, no `RelayState` since none was sent: refused by the model (`SignatureRequired`, M-2) | 467 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-form-2026-10-01.txt` | its `LogoutResponse` to `sp-post`, whose single logout service is published for HTTP-POST alone, signed in its XML under `sign.logout`, its `RelayState` of 80 bytes echoed | 3 987 |

## Keycloak 26.7.4, 1 October 2026

Captured by the judge's second target (`tests/Interop/keycloak/`, section 9.5 of the specification), run with
`castor keycloak --keep` on PHP 8.5.10 between 11:37:23 and 11:37:38 UTC, from a stopped Keycloak, the capture and the
exchange in one start, the messages issued between 11:37:35.702 and 11:37:37.181 UTC. Keycloak generates the keys of
its realms at every start: the metadata of this run, kept with its captures, are the ones that verify them. A query
string and a form are kept as for SimpleSAMLphp above, once this package had read them and the model had validated
them, or refused them as the table says.

`capture.php`: realm sp's broker `idp` and realm idp, as `realms/` configures them, the broker under its defaults.

| File | What | Bytes |
|---|---|---|
| `keycloak-26.7.4-idp-metadata-2026-10-01.xml` | realm idp's metadata as served, its key of this run, HTTP-POST, HTTP-Redirect, SOAP and HTTP-Artifact for its single sign-on and single logout services, `WantAuthnRequestsSigned="true"` | 3 374 |
| `keycloak-26.7.4-sp-metadata-2026-10-01.xml` | the broker `idp`'s metadata as served, no `KeyDescriptor`, `AuthnRequestsSigned="false"` | 1 506 |
| `keycloak-26.7.4-sp-authnrequest-unsigned-refused-query-2026-10-01.txt` | the broker's `AuthnRequest`, unsigned, `SAMLRequest` and `RelayState` (78 bytes): read, then refused by the model (`SignatureRequired`, M-3: realm idp wants it signed, the broker publishes no key) | 626 |
| `keycloak-26.7.4-idp-response-form-2026-10-01.txt` | realm idp's response to it, the response signed and not the assertion, its `RelayState` echoed | 7 751 |
| `keycloak-26.7.4-sp-logoutrequest-unsigned-refused-query-2026-10-01.txt` | the broker's `LogoutRequest`, unsigned, its `RelayState` of 24 bytes: read, then refused by the model (`SignatureRequired`, M-3) | 580 |
| `keycloak-26.7.4-idp-logoutresponse-form-2026-10-01.txt` | realm idp's `LogoutResponse` to it, signed in its XML | 3 697 |

`exchange.php`: realm sp's broker `bindings` and realm idp's client, configured by Keycloak's importers from the
metadata of this package's roles at `https://idp.saml2-bindings.test/` and `https://sp.saml2-bindings.test/`, written
with the test keys of `tests/Fixture/keys/` (`RealDocumentsTest` builds the same roles).

| File | What | Bytes |
|---|---|---|
| `keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml` | the broker `bindings`'s metadata as served, the key of realm sp, `AuthnRequestsSigned="true"`, `WantAssertionsSigned="true"`; the same, but for its `ID`, before and after its "HTTP-POST binding response" is switched on | 2 625 |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-redirect-binding-refused-query-2026-10-01.txt` | the broker's `AuthnRequest` as import-config set it from metadata listing HTTP-Redirect alone, signed: verified, then refused by the model, its `ProtocolBinding` HTTP-Redirect (`Unsupported`, model.md section 8) | 1 100 |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-query-2026-10-01.txt` | the broker's `AuthnRequest` once its response is asked over HTTP-POST, signed, its `RelayState` of 78 bytes | 1 096 |
| `keycloak-26.7.4-sp-logoutrequest-to-bindings-query-2026-10-01.txt` | the broker's `LogoutRequest`, signed, its `RelayState` of 24 bytes | 960 |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-long-relaystate-refused-query-2026-10-01.txt` | the broker's `AuthnRequest` for a client of realm sp whose internal ID is not a UUID, its `RelayState` of 122 bytes: refused by the receiver (`InvalidRelayState`, B-9, SAML Bindings §3.4.3) | 1 124 |
| `keycloak-26.7.4-idp-response-to-bindings-form-2026-10-01.txt` | realm idp's response to this package's service provider, the response signed and not the assertion, its `RelayState` `bindings login ~` echoed | 7 657 |
| `keycloak-26.7.4-idp-logoutresponse-to-bindings-form-2026-10-01.txt` | realm idp's `LogoutResponse` under its client's "Force POST binding", its default, signed in its XML, its `RelayState` `bindings logout ~` echoed | 3 672 |
| `keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt` | realm idp's `LogoutResponse` once "Force POST binding" is off, over HTTP-Redirect, signed over its query string, its `RelayState` of 80 bytes written with `+` for a space and `~` as it is | 993 |
