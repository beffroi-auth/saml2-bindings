# SimpleSAMLphp, both ways

The judge of sub-spike 9b for this package (section 9.5 of `spec/bindings.md`): SimpleSAMLphp accepts what the package
sends over HTTP-Redirect and HTTP-POST, and the package accepts what SimpleSAMLphp sends, as an identity provider and
as a service provider, login and logout. Reproducible from a clean checkout, run by hand with Docker, never a
dependency of the package (nothing here is in the root `composer.json`) and never in the CI (section 12). What it
captured is committed under `tests/Fixture/real/` and checked by `tests/Unit/RealDocumentsTest.php` on every build
(section 9.4).

It is `saml2-model`'s harness (its `tests/Interop/simplesamlphp/`, at commit 9c833c5 of its `main`, 1 October 2026)
with every line that played the binding replaced by this package: that harness inflated, decoded, built the signed
octets and encoded the forms by hand, since this package did not exist yet; here `RedirectSender` writes every URL
sent, `PostSender` every form, `RedirectReceiver` reads every query string received and `PostReceiver` every form.

| | |
|---|---|
| `installation/` | SimpleSAMLphp as an identity provider and as a service provider in containers, copied from `saml2-model` (section 1) |
| `harness.php` | what the two scripts share: the installation's URLs, its test user and its login, over `../harness.php`, what every harness of section 9.5 shares, Keycloak's too: the browser (curl, one cookie jar, one hop at a time), its reading of a page's form with PHP's HTML5 parser, the reading of a query string as it arrived, the captures and the report |
| `capture.php` | SimpleSAMLphp's two parties between themselves, every query string and form read by the package before it is kept (section 3) |
| `exchange.php` | the package and SimpleSAMLphp both ways, login and logout, the probes and the measures (section 4) |
| `../measure.php`, `timing.php` | the measures of the captures, shared with Keycloak's harness, and the figure of section 9.6 (section 5) |
| `.castor/simplesamlphp.php`, at the root | `castor simplesamlphp`: every step above from one task |

The judge was played on 1 October 2026: **green both ways**, on PHP 8.5.10 and on PHP 8.4.25, every probe refused by
SimpleSAMLphp. Section 6 holds the findings.

## Versions

| What | Version | Pinned by | Date |
|---|---|---|---|
| SimpleSAMLphp | 2.5.3.1, slim release archive | `installation/Dockerfile`: the version, and the SHA-256 of the archive, `38d81fc60f358b46a58df38617b02f97f57793dcbf8e491c1abcedb6706ffe3c`, checked by `sha256sum -c` at build | released 9 August 2026, run 1 October 2026 |
| Its SAML library | `simplesamlphp/saml2-legacy` 4.20.3 on `robrichards/xmlseclibs` 3.1.5, what processes every message (`saml2-model`'s finding F-8) | the archive | 1 October 2026 |
| PHP and Apache of the installation | PHP 8.4.26, Apache 2.4.68, Debian 13.7 | `php:8.4.26-apache@sha256:75325cceea4f9a8200f4e9e146e8155ec1b6466b2957b87accf0286b94547cbd` | 1 October 2026 |
| The image | `saml2-bindings-simplesamlphp:2.5.3.1`, built locally from `installation/Dockerfile` | `compose.yaml` | 1 October 2026 |
| This package | `src/` as of d891fbb, on `beffroi-php/saml2-model` `dev-main` at 9c833c5 and `beffroi-php/xml-security` `dev-main` at d7990c0 | the branch `story/8-simplesamlphp` | 1 October 2026 |
| PHP of the scripts | 8.5.10 and 8.4.25, curl 8.14.1, OpenSSL 3.5.7 | `ghcr.io/spomky-labs/phpqa:8.5` and `:8.4`, `PHP_VERSION` of castor | 1 October 2026 |
| Docker, Compose, Castor | Docker 29.8.1, Compose 5.5.1, Castor 1.7.0 (macOS, Apple M4) | the machine that ran it | 1 October 2026 |

## 1. The installation

### What is copied, what differs

Copied from `saml2-model` at 9c833c5, byte for byte: `installation/Dockerfile`, `installation/cert/` (the
installation's two RSA-2048 pairs, disposable and committed on purpose, fingerprints in `saml2-model`'s README), both
`authsources.php` of the identity provider and the test user `student`/`studentpass`, the identity provider's renamed
cookies, `logging.handler`, `session.php`. What differs:

- The compose project is `saml2-bindings-simplesamlphp`, the image `saml2-bindings-simplesamlphp:2.5.3.1`, the
  identity provider on `127.0.0.1:8091` and the service provider on `127.0.0.1:8092`, so that `saml2-model`'s harness
  (8081, 8082) runs beside this one; every entity ID, URL and metadata follows. The `secretsalt` values name this
  package.
- The identity provider publishes its single sign-on and single logout services as SimpleSAMLphp does by default,
  HTTP-Redirect alone (`getGenerated()` of `src/SimpleSAML/Metadata/MetaDataStorageHandler.php`). `saml2-model`'s
  third configuration (`SSP_EXCHANGE`), which published HTTP-POST because the model could only post (its finding
  F-10), and its second (`SSP_SIGN_RESPONSE`), which captured a response whose assertion alone is signed for the
  model, are gone: this judge plays the default.
- This package's roles answer at `http://localhost:8093/bindings/`, where nothing listens: the exchange intercepts every
  message addressed there. Their metadata, written by the model's `MetadataWriter` into `written/` (ignored), mounted
  read-only into both containers at `/var/simplesamlphp/bindings`, are read by SimpleSAMLphp's own parser
  (`SAMLParser::parseDescriptorsString()`), as its metarefresh module reads metadata.
- `capture.sh`, which decoded and verified what it kept by hand inside the identity provider's container
  (`gzinflate()`, `base64_decode()`, `openssl_verify()` over octets it built), is replaced by `capture.php`, which plays
  the same login and logout from the phpqa image and reads every message with this package.
- The model's library half (`library/`) and its `xmlsec1-verify.sh` are not carried over: the XML is the model's to
  judge, and the independent verifier of this package's signatures is the OpenSSL oracle of section 9.1
  (`castor redirect-oracle`).

### The signing options of SimpleSAMLphp 2.5.3.1, read in its source

Read in the image, `modules/saml/src/Message.php` and `vendor/simplesamlphp/saml2-legacy/src/SAML2/HTTPRedirect.php`:

| Option | Where | What it does |
|---|---|---|
| `sign.authnrequest` | the service provider, or the remote identity provider's entry | signs its `AuthnRequest`; over HTTP-Redirect, the query string (`addRedirectSign()`). `SAMLParser::getMetadata20IdP()` draws it from `WantAuthnRequestsSigned="true"` |
| `sign.logout` | either party, or the remote entry | signs its `LogoutRequest` and `LogoutResponse`; over HTTP-Redirect, the query string. Unset on both sides, no logout message is signed (`saml2-model`'s finding F-1) |
| `redirect.sign` | either party, or the remote entry | signs every message sent over HTTP-Redirect when the option of its kind (`sign.authnrequest`, `sign.logout`) is unset on both sides |
| `validate.authnrequest` | the remote service provider's entry, or the identity provider | requires a signature on a received `AuthnRequest`. `SAMLParser::getMetadata20SP()` draws it from `AuthnRequestsSigned="true"` |
| `validate.logout` | the remote entry, or the party | requires a signature on a received logout message |
| `redirect.validate` | the remote entry, or the party | requires a signature on every message received over HTTP-Redirect when the option of its kind is unset on both sides |

The setting that makes the identity provider verify the query string of an `AuthnRequest` is none of them:
`Message::validateMessage()` verifies a signature whenever the request carries a `Signature` parameter
(`isset($_REQUEST['Signature'])`) and the option of its kind is not set to `false` ("to conform to SAML2INT"), and
`HTTPRedirect::receive()` builds the octets it verifies from the raw values of `SAMLRequest` or `SAMLResponse`,
`RelayState` and `SigAlg`, in that order. The `validate.*` options decide the other case, a request that arrives
without a signature: under them it is refused, without them processed. The probes of section 4 measure both (F-2).

### Settings

Everything else is SimpleSAMLphp's distributed default, kept as `config-dist/` in the image and loaded first by each
`config.php` and `authsources.php`.

| Where | Setting | Value | Why |
|---|---|---|---|
| both `config.php` | `secretsalt` | a test value | SimpleSAMLphp refuses to run with the distributed one |
| both `config.php` | `logging.handler` | `errorlog` | the logs go to `docker compose logs` |
| identity provider `config.php` | `module.enable` `exampleauth`, `enable.saml20-idp` | `true` | the test user, the identity provider role |
| identity provider `config.php` | the three session cookie names | `IdPSimpleSAML...` | both parties answer on `localhost`, whose cookies a browser sends to every port |
| `saml20-idp-hosted.php` | entity ID, `privatekey`, `certificate`, `auth` | its metadata URL, `idp.pem`, `idp.crt`, `example-userpass` | nothing else: its default publication, HTTP-Redirect alone, and its signing defaults, the response and the assertion signed |
| `saml20-sp-remote.php` | `default-sp` | static, as its metadata publishes it | the capture |
| `saml20-sp-remote.php` | `bindings/sp`, `bindings/sp-defaults`, `bindings/sp-post` | read from `written/bindings-sp*-metadata.xml`; `AuthnRequestsSigned="true"` becomes `validate.authnrequest` | the three service providers of this package |
| `saml20-sp-remote.php`, the three entries | `validate.logout` | `true` | a logout message of this package that arrives without a signature is refused (`saml2-model`'s finding F-9, F-2 here) |
| `saml20-sp-remote.php`, `bindings/sp` and `bindings/sp-post` | `sign.logout` | `true` | the identity provider signs its logout messages to them, which the model requires (M-2); `bindings/sp-defaults` keeps the default, unsigned, which the judge measures (section 9.5 point 1) |
| `default-sp` (service provider `authsources.php`) | `sign.authnrequest`, `sign.logout` | `true` | the service provider signs its query strings, as in `saml2-model`'s harness |
| `for-bindings` (service provider `authsources.php`) | a second `saml:SP`, `idp` this package's, `sp.pem`, `sp.crt`, `sign.authnrequest`, `sign.logout`, `validate.logout` | `true` for the three | it logs in at this package's identity provider, signs its query strings and refuses an unsigned logout message; its single logout service keeps the default publication, HTTP-Redirect, where this package answers |
| `saml20-idp-remote.php` | `bindings/idp` | read from `written/bindings-idp-metadata.xml`; `WantAuthnRequestsSigned="true"` becomes `sign.authnrequest` | this package's identity provider |
| `sp/session.php`, mounted into `public/` | a page | the session of `for-bindings` as JSON, or `401` | the proof that the service provider opened its session with what this package sent |

This package's roles, written by `exchange.php` with the test keys of `tests/Fixture/keys/`, signed by the key of
their role, every `KeyInfo` left out:

| Role | Entity ID | Endpoints | Flags |
|---|---|---|---|
| identity provider | `http://localhost:8093/bindings/idp` | `SingleSignOnService` `.../idp/sso` and `SingleLogoutService` `.../idp/slo`, HTTP-Redirect | `WantAuthnRequestsSigned="true"` |
| service provider `sp` | `http://localhost:8093/bindings/sp` | `AssertionConsumerService` `.../sp/acs`, HTTP-POST, index 0; `SingleLogoutService` `.../sp/slo`, HTTP-Redirect | `AuthnRequestsSigned`, `WantAssertionsSigned` |
| service provider `sp-defaults` | `http://localhost:8093/bindings/sp-defaults` | the same under its own path | the same |
| service provider `sp-post` | `http://localhost:8093/bindings/sp-post` | the same, its `SingleLogoutService` HTTP-POST alone | the same |

## 2. Commands

```
# The whole judge from a clean checkout: the package's dependencies installed when missing, the image built, the
# installation up, the capture, the exchange, the installation down. PHP 8.5 by default, PHP_VERSION=8.4 for the other.
castor simplesamlphp

# The same, and what SimpleSAMLphp sent kept in tests/Fixture/real/, dated, instead of received/ (ignored)
castor simplesamlphp --keep

# Each step alone
castor simplesamlphp --up
castor simplesamlphp --capture [--keep]
castor simplesamlphp --exchange [--keep]
castor simplesamlphp --timing             # section 5, on the PHP of PHP_VERSION
castor simplesamlphp --down

# What --capture and --exchange run, from the root of the repository
docker run --rm --init --network saml2-bindings-simplesamlphp_default --user "$(id -u):$(id -g)" \
    -e EXCHANGE_CONNECT_TO=localhost:8091:idp:80,localhost:8092:sp:80 -v "$PWD:/project" -w /project \
    ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/exchange.php [--keep]

# The measures and the figure
docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php tests/Interop/measure.php tests/Fixture/real 'simplesamlphp-*.txt'
docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/timing.php
```

`EXCHANGE_CONNECT_TO` pins `localhost:8091` and `localhost:8092` to the two containers at the connection, so that the
`Host` header, every entity ID, every `Destination` and every cookie stay those a browser on the machine sees. The
scripts print one line per step and per measure, and exit with 1 when a step fails: the verdict is read off the run.

## 3. The capture

`capture.php` plays, with one cookie jar, never following a redirect by itself, a login and a logout started by
`default-sp` against the identity provider, the two parties as the installation configures them:

1. Both metadata, from their URLs, kept as served and read with `readTrusted()`.
2. `default-sp`'s login URL: a redirect to the single sign-on service. Its query string goes to
   `RedirectReceiver::authnRequest()`, the model validates it under `default-sp`'s metadata, and it is kept.
3. The login, then the page of the response: the harness reads its form, encodes its fields as a browser does,
   `PostReceiver::response()` reads them as PHP's parser decodes them, the model validates the response, the body is
   kept, and it is posted to `default-sp`, which returns to its `ReturnTo`.
4. `default-sp`'s logout URL: its `LogoutRequest`, read and validated, kept. The identity provider's
   `LogoutResponse` to `default-sp`, read by `RedirectReceiver::logoutMessage()`, unsigned under its defaults, refused
   by the model's `validate()`, kept as a fixture refused; `default-sp` accepts it and closes its session.

On 1 October 2026 (section 4 holds the run): every step green, on both PHP.

## 4. The exchange

### Steps

**This package as a service provider, SimpleSAMLphp's identity provider in front**, once for each of the three
service providers, each in a browser of its own:

1. The identity provider's metadata read live: its single sign-on service is published for HTTP-Redirect alone.
2. The model's `AuthnRequest` (transient `NameIDPolicy`, `AllowCreate`, the HTTP-POST assertion consumer service),
   sent by `RedirectSender` signed with the service provider's test key to the single sign-on service, which verifies
   it and takes it to its login page; the test user logs in; the form of the response is read on the page, its body
   posted by the browser to this package is given to `PostReceiver::response()` and validated by the model.
3. The model's `LogoutRequest` for that session, sent by `RedirectSender` signed to the single logout service; the
   identity provider's `LogoutResponse`, received over HTTP-Redirect by `RedirectReceiver::logoutMessage()`, or over
   HTTP-POST for `sp-post`, read from the form by `PostReceiver::logoutMessage()`, then validated.

The `RelayState` each sends is chosen to measure what the identity provider echoes:

| Service provider | Its logout, by the identity provider | `RelayState` of the login | `RelayState` of the logout |
|---|---|---|---|
| `sp` | signed under `sign.logout`, over HTTP-Redirect | `bindings login ~` | `bindings logout ~` |
| `sp-defaults` | under SimpleSAMLphp's defaults, over HTTP-Redirect | 80 bytes, a space and a `~` among them | none |
| `sp-post` | signed under `sign.logout`, over HTTP-POST | none | 80 bytes |

**This package as an identity provider, SimpleSAMLphp's service provider `for-bindings` in front**, twice, each in a
browser of its own:

1. `for-bindings`'s metadata read live; its login URL, `ReturnTo` its `session.php`: its `AuthnRequest`, over
   HTTP-Redirect signed, received by `RedirectReceiver::authnRequest()` and validated by the model
   (`Authentication::Binding`).
2. The model's response (a transient `NameID` qualified by `for-bindings`, `uid` and `eduPersonAffiliation`,
   SimpleSAMLphp's own windows), written and signed through `PostSender::response()`, its assertion signed the first
   time, the response signed over it the second; the browser posts the `PostForm`'s fields to its action, the
   `RelayState` sent back; `for-bindings` returns to `session.php`, which shows the session open with exactly what the
   package sent.
3. `for-bindings`'s logout URL: its `LogoutRequest`, received and validated, naming the `NameID` and the
   `SessionIndex` the package issued; the model's `LogoutResponse`, sent by `RedirectSender` signed to its single
   logout service for HTTP-Redirect, the `RelayState` sent back; `for-bindings` returns to `session.php`, which then
   answers `401`.

### Results

The run kept, `castor simplesamlphp --keep` on PHP 8.5.10, from 11:03:28 to 11:03:40 UTC on 1 October 2026, the
messages issued between 11:03:33 and 11:03:37 UTC; `PHP_VERSION=8.4 castor simplesamlphp` on PHP 8.4.25 from
11:08:22 to 11:08:30 UTC gave the same outcome. Every step green on both, nineteen steps, three of the capture and
sixteen of the exchange.

| Direction | Step | Outcome |
|---|---|---|
| package as service provider | `AuthnRequest` over HTTP-Redirect, signed by `RedirectSender`, three times | verified by the identity provider in its default publication, taken to its login page |
| | the response form, three times | read by `PostReceiver`, accepted by the model, `SignatureCoverage::AssertionAndResponse`, the `RelayState` echoed as sent, 16 and 80 bytes, absent when none was sent |
| | `LogoutRequest` over HTTP-Redirect, signed by `RedirectSender`, three times | verified, the session ended |
| | `LogoutResponse` to `sp`, over HTTP-Redirect under `sign.logout` | verified by `RedirectReceiver` over the octets as received, `Authentication::Binding`, status `Success`, its `RelayState` `bindings+logout+%7E` returned as `bindings logout ~` |
| | `LogoutResponse` to `sp-defaults`, over HTTP-Redirect under the defaults | read, unsigned, refused by `validate()`: `SignatureRequired`, "The message carries no ds:Signature, which the profile requires (M-2)." |
| | `LogoutResponse` to `sp-post`, over HTTP-POST under `sign.logout` | read by `PostReceiver`, `Authentication::XmlSignature`, status `Success`, its `RelayState` of 80 bytes echoed |
| package as identity provider | `for-bindings`'s `AuthnRequest`, twice | verified by `RedirectReceiver`, `Authentication::Binding` |
| | the response through `PostSender`, assertion signed, then response and assertion signed | `for-bindings` opened its session with the `NameID`, the `SessionIndex` and the attributes the package sent |
| | `for-bindings`'s `LogoutRequest`, twice | verified, `Authentication::Binding`, the `NameID` and `SessionIndex` the package issued |
| | the package's `LogoutResponse` over HTTP-Redirect, signed by `RedirectSender`, twice | verified by `for-bindings`, its session closed |

### Probes

A query string this package signed, accepted as sent, then changed after signing and sent where its genuine twin is
accepted: SimpleSAMLphp must refuse each, so that its acceptance of the genuine ones proves a signature it verified
over the octets of SAML Bindings §3.4.4.1. The message changed is the raw `SAMLRequest` or `SAMLResponse` of another URL
`RedirectSender` wrote, so that no octet is built by hand. On both runs, every probe refused, HTTP 500:

| Changed after signing | `AuthnRequest`, single sign-on service | `LogoutRequest`, single logout service, logged in | `LogoutResponse`, `for-bindings`, its logout pending |
|---|---|---|---|
| the `RelayState` (`bindings-probe` to `bindings-proof`) | refused, "Invalid certificate signature" | refused, the same | refused, the same |
| the `SigAlg`, RSA-SHA256 to RSA-SHA512 | refused, the same | refused, the same | refused, the same |
| the message, another of the package's | refused, the same | refused, the same | refused, the same |
| `Signature` and `SigAlg` removed | refused, "Validation of received messages enabled, but no signature found on message." | refused, the same | refused, the same |

"Invalid certificate signature" is the title of SimpleSAMLphp's error `NOTVALIDCERTSIGNATURE`, which
`Message::checkSign()` raises whatever made the verification fail. After the refused `LogoutRequest` probes the
session stayed open and the genuine `LogoutRequest` ended it; after the refused `LogoutResponse` probes the genuine one
closed `for-bindings`'s session.

### Measures (section 9.5 point 4)

**The `SigAlg` SimpleSAMLphp sends**: RSA-SHA256 in every signed query string, its service provider's and its identity
provider's (`signature.algorithm`, its default).

**The `SigAlg` it accepts**, at the single sign-on service, each `AuthnRequest` in a browser of its own, accepted when
taken to the login page:

| `SigAlg` | Signed by | PHP 8.5.10 | PHP 8.4.25 |
|---|---|---|---|
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | `RedirectSender` | accepted | accepted |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` | `RedirectSender` | accepted | accepted |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` | `RedirectSender` | accepted | accepted |
| `http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1` (RSASSA-PSS) | `RedirectSender` | refused, "Invalid certificate signature" | not measured, the build lacks it |
| `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | hand, SHA-1 | accepted | accepted |
| `http://www.w3.org/2001/04/xmlenc#rsa-1_5`, an encryption algorithm | hand, SHA-1 | accepted | accepted |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha224` | hand, SHA-224 | refused, the same | refused, the same |
| `urn:example:unknown-signature-algorithm` | hand, SHA-256 | refused, the same | refused, the same |

**`RelayState`**: what each party sends, and how the identity provider decodes it.

- The service provider sends its `ReturnTo` as the `RelayState` of its `AuthnRequest`, escaped by `urlencode()`: 44 and
  56 bytes for the `ReturnTo` of the run, 105 bytes for a `ReturnTo` of 105 bytes, which `RedirectReceiver` refused on
  1 October 2026 (`InvalidRelayState`, B-9) and reads since 12 October 2026 (F-5). An empty or an absent `ReturnTo` is answered with HTTP 400 "Bad request received",
  no `AuthnRequest`. The `RelayState` of its `LogoutRequest` is an ID of its own state, 43 bytes.
- The identity provider echoes the `RelayState` it received: 16 and 80 bytes in its forms, 17 bytes in its redirect,
  intact; when none was received, none is sent, neither in its form nor in its query string. SimpleSAMLphp never sent
  an empty `RelayState`.
- A space in a signed `RelayState`, written `%20` by `RedirectSender` and `+` by hand: both decoded to a space
  (`urldecode()` of `HTTPRedirect::parseQuery()`), echoed as `a b` in the form.

**Escaping**: every query string SimpleSAMLphp wrote is in uppercase hexadecimal, its parameters in the order
`SAMLRequest` or `SAMLResponse`, `RelayState`, `SigAlg`, `Signature`, nothing else; a space is `+` and a `~` is `%7E`,
since it escapes with PHP's `urlencode()` (`HTTPRedirect::getRedirectURL()`): the `RelayState` `bindings logout ~`
arrived as `bindings+logout+%7E` (F-1).

**Forms**: the base64 of every form, the response's and the logout response's, on one line, never wrapped; the fields
`SAMLResponse`, then `RelayState` when there is one; the submit button of the page carries no name, so a browser posts
those two fields only.

## 5. Measurements

`../measure.php` on the captures of `tests/Fixture/real/`, 1 October 2026 (section 2 has the command):

| Query string | Bytes | Parameters | SigAlg | Escapes | RelayState, bytes | Signature, bytes | Inflated, bytes |
|---|---|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-query-2026-10-01.txt` | 944 | SAMLResponse, RelayState, SigAlg, Signature | rsa-sha256 | 35, uppercase; 2 `+`, 1 `%7E` | 17 | 256 | 542 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-unsigned-refused-query-2026-10-01.txt` | 467 | SAMLResponse | none | 13, uppercase; 0 `+`, 0 `%7E` | absent | none | 551 |
| `simplesamlphp-2.5.3.1-idp-logoutresponse-unsigned-refused-query-2026-10-01.txt` | 522 | SAMLResponse, RelayState | none | 11, uppercase; 0 `+`, 0 `%7E` | 43 | none | 586 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-query-2026-10-01.txt` | 986 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 39, uppercase; 0 `+`, 0 `%7E` | 56 | 256 | 599 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt` | 1 041 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 46, uppercase; 0 `+`, 0 `%7E` | 105 | 256 | not read: B-9 refuses it before inflating (569 by a decoder outside the harness) |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt` | 978 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 45, uppercase; 0 `+`, 0 `%7E` | 44 | 256 | 569 |
| `simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt` | 952 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 32, uppercase; 0 `+`, 0 `%7E` | 44 | 256 | 560 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-query-2026-10-01.txt` | 1 061 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 35, uppercase; 0 `+`, 0 `%7E` | 43 | 256 | 727 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-bindings-query-2026-10-01.txt` | 1 053 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 33, uppercase; 0 `+`, 0 `%7E` | 43 | 256 | 700 |
| `simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt` | 1 073 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 45, uppercase; 0 `+`, 0 `%7E` | 43 | 256 | 691 |

| Form, the body a browser posts | Bytes | Fields | Message, base64 characters | Line breaks | RelayState, bytes |
|---|---|---|---|---|---|
| `simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-form-2026-10-01.txt` | 3 987 | SAMLResponse, RelayState | 3 860 | none | 80 |
| `simplesamlphp-2.5.3.1-idp-response-form-2026-10-01.txt` | 9 781 | SAMLResponse, RelayState | 9 624 | none | 56 |
| `simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt` | 9 519 | SAMLResponse, RelayState | 9 412 | none | 16 |

The URLs this package sent in the run measure 980 to 1 090 bytes of query string for an `AuthnRequest` signed under
RSA-SHA256 with a `RelayState` of up to 80 bytes. Against the bounds of section 7 of the specification: query strings
of 467 to 1 073 bytes under `maxQueryStringBytes` 8 192, about an eighth of it; messages of 542 to 727 bytes inflated
under `maxInflatedBytes` 65 536; form values of 3 860 to 9 624 characters under `maxFormValueBytes` 1 572 864; every
`Signature` of 256 bytes, an RSA-2048 key, its text of 344 characters under 1 368; `RelayState` of 16 to 80 bytes, and
105 bytes from the service provider's long `ReturnTo` (F-5).

`timing.php`, the figure of section 9.6 (the metadata read once, the `Loader`, the receiver and the validator made at
each run, a new replay store, the clock frozen at the capture, 20 runs to warm up, then 500), on an Apple M4 under
Docker Desktop, 1 October 2026:

| PHP, OpenSSL | `AuthnRequest` of `for-bindings`, query string to `AcceptedAuthnRequest`: median, 95th percentile | `AuthnRequest` of `default-sp`: median, 95th percentile | Beside it, the response form to `AcceptedAssertion`, two signatures: median, 95th percentile |
|---|---|---|---|
| 8.5.10, OpenSSL 3.5.7 | 0.17 ms, 0.18 ms | 0.17 ms, 0.18 ms | 0.50 ms, 0.52 ms |
| 8.4.25, OpenSSL 3.5.7 | 0.17 ms, 0.18 ms | 0.17 ms, 0.18 ms | 0.50 ms, 0.52 ms |

About thirty times under the provisional 5 ms of section 9.6. The response form, a document of 7 KB whose response and
assertion are both verified, takes three times as long as the query string of an `AuthnRequest`, one verification of
a few hundred bytes.

## 6. Findings

No genuine message the judge needed was refused by either side, and no rule of the specification had to change for
the exchange. What was measured, against sections 4, 6, 7, 8 and 12 of the specification:

- **F-1. SimpleSAMLphp escapes with `urlencode()`, not RFC 3986.** `HTTPRedirect::getRedirectURL()` writes each value
  with PHP's `urlencode()`: uppercase hexadecimal, a space as `+`, a `~` as `%7E`. On base64 and on URLs without space
  or tilde, the two encodings coincide, which is why the captures of 30 September showed uppercase hexadecimal only;
  the `RelayState` `bindings logout ~` shows the difference (`bindings+logout+%7E`). `RedirectReceiver` verified it over
  the octets as received and decoded the `+` to a space (B-2, B-8); SimpleSAMLphp decoded this package's `%20` and a
  `+` alike. Section 6.3, which said this package's RFC 3986 escaping is how SimpleSAMLphp writes its query strings,
  is corrected; the rule does not change.
- **F-2. SimpleSAMLphp verifies a query string's signature whenever there is one; `validate.*` decides the unsigned
  case.** `Message::validateMessage()` verifies when a `Signature` parameter is present unless `validate.authnrequest`
  or `validate.logout` is `false`, and requires one only under them (or `redirect.validate`). The probes measure both:
  a `RelayState`, a `SigAlg` or a message changed after signing is refused under any setting, a query string stripped
  of its `Signature` and `SigAlg` is refused only because the entries facing this package set `validate.logout` and
  `AuthnRequestsSigned="true"` sets `validate.authnrequest`. `saml2-model`'s finding F-9, a logout message whose
  signature fails read as unsigned, is about the XML signature of HTTP-POST; over HTTP-Redirect a failing signature is
  refused, and only its absence needs `validate.logout`. For `beffroi/saml` (section 6.8): a SimpleSAMLphp service
  provider without `validate.logout` accepts an unsigned logout message from anyone.
- **F-3. The `SigAlg` SimpleSAMLphp accepts include RSA-SHA1 and an encryption URI.** It sends RSA-SHA256 by default
  and accepts RSA-SHA256, RSA-SHA384, RSA-SHA512, RSA-SHA1, and `http://www.w3.org/2001/04/xmlenc#rsa-1_5`, the URI of
  RSA PKCS#1 v1.5 encryption, which it verifies under SHA-1 (`Utils::castKey()` lists these five; `xmlseclibs`
  verifies a key without a digest under SHA-1). It refuses RSASSA-PSS, RSA-SHA224 and an unknown URI, even signed
  under SHA-256: no default algorithm. This package sends RSA-SHA256 by default, what SimpleSAMLphp sends, and refuses
  RSA-SHA1 (B-3): a SimpleSAMLphp configured with `signature.algorithm` RSA-SHA1 would be refused, a case for
  sub-spikes 9c and 9d (section 12), never an option.
- **F-4. No empty `RelayState`.** SimpleSAMLphp's identity provider sends a `RelayState` only when it received one, in
  its forms and its query strings alike (`HTTPPost::send()`, `HTTPRedirect::getRedirectURL()`: `$relayState !==
  null`), and its service provider refuses a login without `ReturnTo` (HTTP 400). B-9 refuses an empty `RelayState`
  (section 12, decided on 1 October 2026); SimpleSAMLphp never sends one, so that the decision stands measured.
- **F-5. SimpleSAMLphp's service provider sends a `RelayState` longer than 80 bytes.** It sends its `ReturnTo` as the
  `RelayState` of its `AuthnRequest`, whatever its length: a `ReturnTo` of 105 bytes was sent as a `RelayState` of 105
  bytes, which `RedirectReceiver` refused on 1 October 2026 (`InvalidRelayState`, B-9), as SAML Bindings §3.4.3 says
  the value "MUST NOT exceed 80 bytes in length"; `beffroi/saml` as an identity provider would have refused the login of
  a SimpleSAMLphp service provider whose application returns to a URL longer than 80 bytes. Decided on 12 October 2026
  by the maintainer, with K-4 of Keycloak (section 12 of the specification): B-9 reads and sends a `RelayState` of up
  to 1 024 bytes, a named and bounded exception to the binding (section 8), so that the capture, kept as
  `simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt`, is verified and validated
  (section 9.4).
- **F-6. The identity provider's `LogoutResponse` is unsigned under its defaults, over HTTP-Redirect too.**
  `saml2-model`'s finding F-1, measured on the query string: under the defaults the identity provider's
  `LogoutResponse` carries `SAMLResponse` and `RelayState` and no `SigAlg` or `Signature`; `RedirectReceiver` reads it,
  and the model's `validate()` refuses it (`SignatureRequired`, M-2), to `default-sp` in the capture and to `sp-defaults`
  in the exchange. SimpleSAMLphp's own `default-sp` accepted it (no `validate.logout`). Under `sign.logout` the same
  answer is signed over its query string and accepted (`Authentication::Binding`), and over HTTP-POST signed in its
  XML (`Authentication::XmlSignature`).
- **F-7. HTTP-Redirect alone is enough.** The identity provider in its default publication, HTTP-Redirect alone for its
  single sign-on and single logout services, accepted every `AuthnRequest` and `LogoutRequest` this package signed over
  its query string, and `for-bindings`, in its default publication too, every `LogoutResponse`: `saml2-model`'s finding
  F-10, which needed HTTP-POST published, is answered by this package.
- **F-8. SimpleSAMLphp reads the metadata of this package's roles as the model writes them.** Signed, `KeyInfo` left
  out of every message: both parties verified every query string and every XML signature under the key of the
  metadata, as `saml2-model` found for its documents (its F-11, F-12). SimpleSAMLphp's service provider takes the
  response's attribute values without `xsi:type` (`saml2-model`'s F-13).

`RealDocumentsTest` reads every capture of this run with the receivers of this package and validates it with the model
under a clock frozen at its capture; `tests/Fixture/real/README.md` lists them.
