# Keycloak, reinforcing the judge

The second target of the judge of sub-spike 9b for this package (section 9.5 of `spec/bindings.md`): Keycloak accepts
what the package sends over HTTP-Redirect and HTTP-POST, and the package accepts what Keycloak sends, as an identity
provider (realm `idp`) and as a service provider (realm `sp`, whose SAML identity providers broker its logins), login
and logout. It reinforces the judge, SimpleSAMLphp both ways (`../simplesamlphp/README.md`), without being a condition
of it, as for `saml2-model`: every refusal either way is a finding below, never a reason to loosen a rule outside the
specification. Run by hand with Docker, never a dependency of the package and never in the CI (section 12). What it
captured is committed under `tests/Fixture/real/` and checked by `tests/Unit/RealDocumentsTest.php` on every build
(section 9.4).

It is `saml2-model`'s Keycloak harness (its `tests/Interop/keycloak/`, story #14 of its epic, at commit 9c833c5 of its
`main`, 1 October 2026), which played every message over HTTP-POST, base64 in a form field, and left every HTTP-Redirect
exchange to this package: here `RedirectSender` writes every URL sent, `PostSender` every form, `RedirectReceiver` reads
every query string received and `PostReceiver` every form.

| | |
|---|---|
| `compose.yaml`, `realms/` | Keycloak and its two realms, copied from `saml2-model` (section 1) |
| `harness.php` | what the two scripts share: Keycloak's URLs, its test user and its login, the OpenID Connect client that starts a login at realm `sp`, the admin REST API, Keycloak's error page; over `../harness.php`, what every harness of section 9.5 shares, SimpleSAMLphp's too: the browser (curl, one cookie jar, one hop at a time), its reading of a page's form with PHP's HTML5 parser, the raw reading of a query string, the captures and the report |
| `capture.php` | realm `sp`'s broker and realm `idp` between themselves, every query string and form read by the package before it is kept (section 3) |
| `exchange.php` | Keycloak configured from this package's metadata by its own importers, then the package and Keycloak both ways, login and logout, the probes and the measures (section 4) |
| `../measure.php` | the measures of the captures (section 5) |
| `.castor/keycloak.php`, at the root | `castor keycloak`: every step above from one task |

The judge was played on 1 October 2026: **green both ways**, on PHP 8.5.10 and on PHP 8.4.25, every probe refused by
Keycloak, its `LogoutResponse` over HTTP-Redirect obtained, verified and accepted. Two settings of Keycloak's console
were changed for it, each a measured finding: as its importer configures it, the broker asks for its response over
HTTP-Redirect, which the model refuses (K-2), and realm `idp` answers a logout over HTTP-POST (K-9). Section 6 holds
the findings.

## Versions

| What | Version | Pinned by | Date |
|---|---|---|---|
| Keycloak | 26.7.4, `quay.io/keycloak/keycloak:26.7.4`, manifest `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c`, published on 16 September 2026, the highest release of the registry on 30 September 2026 (`saml2-model`'s README says how it was chosen) | `compose.yaml`, the image by its manifest | run 1 October 2026 |
| Mode | `start-dev`: HTTP, the H2 database inside the container, the realms imported at its first start from `realms/`, their keys generated then | `compose.yaml` | 1 October 2026 |
| This package | `src/` as of d891fbb, on `beffroi-php/saml2-model` `dev-main` at 9c833c5 and `beffroi-php/xml-security` `dev-main` at d7990c0 | the branch `story/9-keycloak` | 1 October 2026 |
| PHP of the scripts | 8.5.10 and 8.4.25, curl 8.14.1, OpenSSL 3.5.7 | `ghcr.io/spomky-labs/phpqa:8.5` and `:8.4`, `PHP_VERSION` of castor | 1 October 2026 |
| Docker, Compose, Castor | Docker 29.8.1, Compose 5.5.1, Castor 1.7.0 (macOS, Darwin 25.6, Apple M4) | the machine that ran it | 1 October 2026 |

## 1. The installation

### What is copied, what differs

Copied from `saml2-model` at 9c833c5: `compose.yaml` (the image by its manifest, `start-dev`, the disposable
administrator `admin`/`admin`, the loopback only) and `realms/idp.json` and `realms/sp.json` byte for byte but for their
URLs: realm `idp` with its test user `alice`/`alice` and its SAML client for realm `sp`'s broker, realm `sp` with its
SAML identity provider `idp` pointing at realm `idp`, its first broker login flow without review, and its public OpenID
Connect client `capture`. `saml2-model`'s README sets out, measured, why the realm files write Keycloak's defaults out
(an import applies none) and each setting that differs from them; nothing of it changes here. What differs:

- The compose project is `saml2-bindings-keycloak` and the port 8190, `--http-port=8190` inside the container and
  `127.0.0.1:8190` on the host, so that `saml2-model`'s harness (8180) runs beside this one; every URL of the realms
  follows (`http://localhost:8190/realms/idp`, `.../realms/sp`, `.../capture`).
- The scripts run in the phpqa image inside the network namespace of the Keycloak container, as `saml2-model`'s
  exchange did, so that `localhost:8190` names Keycloak there as in every URL it builds and checks.
- `capture.sh`, which decoded what it kept with perl (base64 and raw inflate), is replaced by `capture.php`, which plays
  the same login and logout and reads every message with this package; `verify.sh`, xmlsec1 over Keycloak's XML, is
  not carried over: the XML is the model's to judge, and the independent verifier of this package's signatures is the
  OpenSSL oracle of section 9.1 (`castor redirect-oracle`).
- This package's roles answer at `https://idp.saml2-bindings.test/` and `https://sp.saml2-bindings.test/`, where nothing
  listens (`saml2-model`'s answered at `https://idp.saml2-model.test/` and `https://sp.saml2-model.test/`): Keycloak
  redirects or posts there through the browser only, and the exchange reads what it sends.

### This package's roles, and what Keycloak's importers make of them

Written by `exchange.php` with the model's `MetadataWriter` and the test keys of `tests/Fixture/keys/`, each signed by
the key of its role, every `KeyInfo` left out, into `written/` (ignored), then given to Keycloak through the admin REST
API, as an administrator who imports a metadata file in the console:

| Role | Entity ID | Endpoints | Flags |
|---|---|---|---|
| identity provider | `https://idp.saml2-bindings.test/metadata` | `SingleSignOnService` `.../sso` and `SingleLogoutService` `.../slo`, HTTP-Redirect alone | `WantAuthnRequestsSigned="true"`; `NameIDFormat` persistent |
| service provider | `https://sp.saml2-bindings.test/metadata` | `AssertionConsumerService` `.../acs`, HTTP-POST, index 0, default; `SingleLogoutService` `.../slo`, HTTP-Redirect then HTTP-POST | `AuthnRequestsSigned="true"`, `WantAssertionsSigned="false"`; `NameIDFormat` persistent |

- **Realm `sp`, identity provider `bindings`.** `POST /admin/realms/sp/identity-provider/import-config` (multipart,
  `providerId=saml`) returns what Keycloak draws from the identity provider metadata; `POST
  /admin/realms/sp/identity-provider/instances` creates the identity provider with it, over the defaults of the
  console's form that the import does not return (`entityId` the realm URL, `wantAssertionsSigned=true`,
  `nameIDPolicyFormat` persistent, `principalType=SUBJECT`, `allowCreate=true`, `allowedClockSkew=0`,
  `attributeConsumingServiceIndex=0`, as `saml2-model`'s exchange) and the first broker login flow without review of
  `realms/sp.json`. Before it, the same import is measured on the metadata listing HTTP-Redirect then HTTP-POST.
- **Realm `idp`, client `https://sp.saml2-bindings.test/metadata`.** `POST /admin/realms/idp/client-description-converter`
  (the service provider metadata as the body) returns a client representation; `POST /admin/realms/idp/clients`
  creates it, and the server adds its defaults to what the converter did not set.

The identity provider, the user `bindings-alice` the subject became in realm `sp` on an earlier run, and the client are
deleted first when they exist, so that an exchange runs again on a live container (`saml2-model`'s finding 28). What
the importers set, read back on 1 October 2026:

| Where | Setting | Value | From |
|---|---|---|---|
| realm `sp`, identity provider `bindings` | `postBindingAuthnRequest`, `postBindingResponse`, `postBindingLogout` | `false`, `false`, `false`; `true`, `true`, `true` for the metadata listing HTTP-Redirect then HTTP-POST | import-config, from the bindings of the single sign-on service (K-1) |
| | `wantAuthnRequestsSigned`, `validateSignature`, `signingCertificate` | `true`, `true`, the identity provider test certificate | import-config, from `WantAuthnRequestsSigned="true"` and the `KeyDescriptor` |
| | `singleSignOnServiceUrl`, `singleLogoutServiceUrl`, `idpEntityId`, `nameIDPolicyFormat` | this package's two services, its entity ID, persistent | import-config |
| | `addExtensionsElementWithKeyInfo`, `artifactBindingResponse`, `loginHint`, `enabledFromMetadata` | `false`, `false`, `false`, `true` | import-config |
| realm `idp`, client of this package | `saml.client.signature` ("Client signature required") | `true` | the converter, from `AuthnRequestsSigned="true"` |
| | `saml_assertion_consumer_url_post`, `saml_single_logout_service_url_redirect`, `saml_single_logout_service_url_post`, `saml.signing.certificate`, `saml_name_id_format` | the consumer service, the logout service twice, the service provider test certificate, `persistent` | the converter |
| | `saml.server.signature`, `saml.signature.algorithm`, `saml.authnstatement`, `saml.server.signature.keyinfo.ext` | `true`, `RSA_SHA256`, `true`, `false` | the converter |
| | `saml.force.post.binding`, `saml_force_name_id_format`, `saml.allow.ecp.flow`, `saml_signature_canonicalization_method`, `frontchannelLogout` | `true`, `false`, `false`, exc-c14n, on | the server's defaults |

### The two settings changed in the console, and why

| Where | Setting | As imported | Here | Why |
|---|---|---|---|---|
| realm `sp`, identity provider `bindings` | `postBindingResponse` ("HTTP-POST binding response") | `false` | `true`, after the first step of the exchange | As import-config sets it from metadata listing HTTP-Redirect alone, the broker asks for its response over HTTP-Redirect (`ProtocolBinding`), which the model refuses (model.md section 8, `saml2-model`'s finding 1), and metadata listing HTTP-POST too turns every binding of the broker to HTTP-POST (K-1, K-2). This one switch keeps the broker's `AuthnRequest` and `LogoutRequest` on HTTP-Redirect, signed, and asks for the response over HTTP-POST. It changes nothing in the broker's metadata but its `ID` (measured) |
| realm `idp`, client of this package | `saml.force.post.binding` ("Force POST binding") | `true`, the server's default | `false`, after the first logout of direction 2 | Under the default, realm `idp` answers every logout over HTTP-POST. Off, it answers a `LogoutRequest` received over HTTP-Redirect over HTTP-Redirect, to the client's redirect logout URL the converter set (K-9). The login response stays over HTTP-POST, which the `AuthnRequest` asks for |

Each switch is a setting an administrator changes in Keycloak's console; neither changes a rule of this package or of
the model.

## 2. Commands

```
# The whole run from a clean checkout: the package's dependencies installed when missing, Keycloak up with new realm
# keys, the capture, the exchange, Keycloak down. PHP 8.5 by default, PHP_VERSION=8.4 for the other.
castor keycloak

# The same, and what Keycloak sent kept in tests/Fixture/real/, dated, instead of received/ (ignored); capture and
# exchange in one start, since the metadata of the run verify its captures
castor keycloak --keep

# Each step alone
castor keycloak --up
castor keycloak --capture [--keep]
castor keycloak --exchange [--keep]
castor keycloak --down

# What --capture and --exchange run, from the root of the repository
docker run --rm --init --network container:$(docker compose -f tests/Interop/keycloak/compose.yaml ps -q keycloak) \
    --user "$(id -u):$(id -g)" -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php tests/Interop/keycloak/exchange.php [--keep]

# The measures
docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php tests/Interop/measure.php tests/Fixture/real 'keycloak-*.txt'
```

The scripts wait for Keycloak (180 s at most), print one line per step and per measure, and exit with 1 when a step
fails: the verdict is read off the run.

## 3. The capture

`capture.php` plays, with one cookie jar, never following a redirect by itself, a login and a logout of the client
`capture` of realm `sp` through its broker `idp` against realm `idp`, the two realms as `realms/` configures them, the
broker under its defaults:

1. Both metadata, from their URLs, kept as served and read with `readTrusted()`.
2. The login at the client, `kc_idp_hint=idp`: realm `sp` redirects to realm `idp`'s single sign-on service. Its query
   string goes to `RedirectReceiver::authnRequest()`, and the model refuses it, kept as a fixture refused.
3. The login at realm `idp`, then the page of the response: the harness reads its form, encodes its fields as a browser
   does, `PostReceiver::response()` reads them as PHP's parser decodes them, the model validates the response, the body
   is kept, and it is posted to the broker, which ends at the client with its code.
4. The logout at the client: the broker's `LogoutRequest`, read by `RedirectReceiver::logoutMessage()`, refused by the
   model, kept refused; realm `idp`'s `LogoutResponse` form, read by `PostReceiver::logoutMessage()` and validated,
   kept, posted to the broker, which ends at the client.

The model refuses the broker's two requests, so no accepted message carries their `ID`: `capture.php` reads the `ID`
attribute of the refused document, `Document::root()`, to pair realm `idp`'s answer with it (`ExpectedResponse`,
`InResponseTo`). That one read of the XML is the harness's, an observer between two Keycloaks, and decides nothing.

On 1 October 2026: every step green, on both PHP; the two refusals are `saml2-model`'s findings 1 and 2 seen through the
binding (K-11).

## 4. The exchange

### Steps

**Keycloak configured** from this package's metadata by its importers (section 1), then realm `idp`'s metadata read
live, kept, and read with `readTrusted()`.

**This package as an identity provider, realm `sp`'s broker `bindings` in front:**

1. The broker as import-config set it, HTTP-Redirect throughout: the login at the client `capture`, `kc_idp_hint=bindings`;
   the broker's metadata read live and kept; its signed `AuthnRequest` received by `RedirectReceiver::authnRequest()`,
   its signature verified, then refused by the model's `validate`, its `ProtocolBinding` HTTP-Redirect; kept refused.
2. The broker's "HTTP-POST binding response" switched on (section 1); its metadata read again.
3. The login again: the `AuthnRequest`, over HTTP-Redirect signed, received by `RedirectReceiver` and validated by the
   model (`Authentication::Binding`); the model's response (the persistent subject `bindings-alice`, conditions and a
   bearer window of 300 s from the second of issue, the broker allowing no skew, two attributes without `xsi:type`),
   written and signed through `PostSender::response()`, its assertion signed as the broker wants; the browser posts the
   `PostForm`'s fields to its action with the broker's `RelayState`; the first broker login creates the user, the client
   gets its code, and realm `sp`'s userinfo endpoint names `bindings-alice`.
4. The logout at the client: the broker's `LogoutRequest`, over HTTP-Redirect signed, received by
   `RedirectReceiver::logoutMessage()` and validated, naming the `NameID` and the `SessionIndex` the package issued; the
   model's `LogoutResponse`, sent by `RedirectSender` signed to the broker's single logout service for HTTP-Redirect with
   its `RelayState`, first changed after signing (the probes below), then as written: the broker ends at the client, and
   realm `sp`'s userinfo endpoint refuses the access token, the session closed.
5. A measure: the same login started at an OpenID Connect client of realm `sp` created with an internal ID that is not a
   UUID, and the `RelayState` of the broker's `AuthnRequest`.

**This package as a service provider, realm `idp` in front:**

1. The model's `AuthnRequest` (persistent `NameIDPolicy`, `AllowCreate`, HTTP-POST as `ProtocolBinding`), sent by
   `RedirectSender` signed with the service provider test key to realm `idp`'s single sign-on service for HTTP-Redirect,
   with the `RelayState` `bindings login ~`; realm `idp` verifies it and shows its login page; `alice` logs in; the form
   of the response is read on the page, its body given to `PostReceiver::response()` and validated by the model.
2. The model's `LogoutRequest` for that session, sent by `RedirectSender` signed to realm `idp`'s single logout service
   for HTTP-Redirect, first changed after signing (the probes below), then as written, with the `RelayState`
   `bindings logout ~`; realm `idp`'s `LogoutResponse`, under its client's "Force POST binding", read from its form by
   `PostReceiver::logoutMessage()` and validated.
3. "Force POST binding" switched off (section 1).
4. A login without `RelayState`, then a logout with a `RelayState` of 80 bytes: realm `idp`'s `LogoutResponse`, over
   HTTP-Redirect, received by `RedirectReceiver::logoutMessage()` and validated.

### Results

The run kept, `castor keycloak --keep` on PHP 8.5.10, from a stopped Keycloak, the capture from 11:37:23 UTC and the
exchange from 11:37:36 to 11:37:38 UTC on 1 October 2026, the messages issued between 11:37:35.702 and 11:37:37.181 UTC;
`PHP_VERSION=8.4 castor keycloak` on PHP 8.4.25, from 11:38:01 UTC, gave the same outcome but for the measures of
RSASSA-PSS, which that build lacks. Every step green on both, eighteen steps, three of the capture and fifteen of the
exchange.

| Direction | Step | Outcome |
|---|---|---|
| package as identity provider | the broker's `AuthnRequest` as import-config set it | signed over its query string, verified by `RedirectReceiver`, refused by the model: `Unsupported`, "The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8)." (K-2) |
| | the broker's `AuthnRequest`, "HTTP-POST binding response" on | signed over its query string, verified by `RedirectReceiver`, `Authentication::Binding`, `ProtocolBinding` HTTP-POST, its assertion consumer service resolved to the HTTP-POST one of the broker's metadata (index 2) |
| | the response through `PostSender`, the assertion signed | accepted by the broker: the first broker login created `bindings-alice` and the client got its tokens |
| | the broker's `LogoutRequest` | signed over its query string, verified, `Authentication::Binding`, the `NameID` and the `SessionIndex` the package issued |
| | the package's `LogoutResponse` over HTTP-Redirect, signed by `RedirectSender` | verified by the broker, its session closed, back at the client |
| package as service provider | `AuthnRequest` over HTTP-Redirect, signed by `RedirectSender`, twice | verified by realm `idp` under the client's certificate, taken to its login page |
| | the response form, twice | read by `PostReceiver`, accepted by the model, `SignatureCoverage::Response`, a persistent `NameID`, six `Role` attributes; the `RelayState` echoed as sent, 16 bytes, absent when none was sent |
| | `LogoutRequest` over HTTP-Redirect, signed by `RedirectSender`, twice | verified, the session ended |
| | `LogoutResponse` under "Force POST binding" | over HTTP-POST, read by `PostReceiver`, `Authentication::XmlSignature`, status `Success`, its `RelayState` `bindings logout ~` echoed |
| | `LogoutResponse`, "Force POST binding" off | over HTTP-Redirect, signed over its query string, verified by `RedirectReceiver` over the octets as received, `Authentication::Binding`, status `Success`, its `RelayState` of 80 bytes written with `+` for a space and returned as sent (K-9) |

### Probes

A query string this package signed, accepted as sent, then changed after signing and sent where its genuine twin is
accepted: Keycloak must refuse each, so that its acceptance of the genuine ones proves a signature it verified over the
octets of SAML Bindings §3.4.4.1. The message changed is the raw `SAMLRequest` or `SAMLResponse` of another URL
`RedirectSender` wrote, so that no octet is built by hand. On both runs, every probe refused, HTTP 400, and its genuine
twin accepted:

| Changed after signing | `AuthnRequest`, realm `idp`'s single sign-on service | `LogoutRequest`, realm `idp`'s single logout service, logged in | `LogoutResponse`, the broker, its logout pending |
|---|---|---|---|
| the `RelayState` (`bindings-probe` to `bindings-proof`, or the broker's to `bindings-proof`) | refused, "Invalid requester" | refused, the same | refused, "Invalid signature in response from identity provider." |
| the `SigAlg`, RSA-SHA256 to RSA-SHA512 | refused, the same | refused, the same | refused, the same |
| the message, another of the package's | refused, the same | refused, the same | refused, the same |
| `Signature` and `SigAlg` removed | refused, the same | refused, the same | refused, the same |

"Invalid requester" is the message of realm `idp`'s error page for a request whose signature fails, "Invalid signature
in response from identity provider." the broker's. After the refused `LogoutRequest` probes the genuine `LogoutRequest`
ended the session; after the refused `LogoutResponse` probes the genuine one closed realm `sp`'s.

### Measures (section 9.5 point 4)

**The `SigAlg` Keycloak sends**: RSA-SHA256 in every signed query string, the broker's and realm `idp`'s (the broker's
`signatureAlgorithm` and the client's `saml.signature.algorithm`, `RSA_SHA256` by default).

**The `SigAlg` realm `idp` accepts**, at its single sign-on service, each `AuthnRequest` in a browser of its own,
accepted when taken to the login page:

| `SigAlg` | Signed by | PHP 8.5.10 | PHP 8.4.25 |
|---|---|---|---|
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | `RedirectSender` | accepted | accepted |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha384` | `RedirectSender` | refused, "Invalid requester" | refused, the same |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` | `RedirectSender` | accepted | accepted |
| `http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1` (RSASSA-PSS) | `RedirectSender` | accepted | not measured, the build lacks it |
| `http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1` | `RedirectSender` | refused, the same | not measured, the build lacks it |
| `http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1` | `RedirectSender` | accepted | not measured, the build lacks it |
| `http://www.w3.org/2000/09/xmldsig#rsa-sha1` | hand, SHA-1 | accepted | accepted |
| `http://www.w3.org/2001/04/xmlenc#rsa-1_5`, an encryption algorithm | hand, SHA-1 | refused, the same | refused, the same |
| `http://www.w3.org/2001/04/xmldsig-more#rsa-sha224` | hand, SHA-224 | refused, the same | refused, the same |
| `urn:example:unknown-signature-algorithm` | hand, SHA-256 | refused, the same | refused, the same |

**`RelayState`**: what each party sends, and how realm `idp` decodes it.

- The broker sends its own state as the `RelayState` of its `AuthnRequest`: 78 bytes every time, its authentication
  session's code (43 characters), its tab (11) and its client's internal ID, a UUID written as the base64url of its 16
  bytes (22), joined by dots (`IdentityBrokerState.decoded()` of 26.7.4; its SAML provider declares no long state,
  `supportsLongStateParameter()` false). For a client whose internal ID is not a UUID, Keycloak writes the base64url of
  its `client_id` instead: 122 bytes for a `client_id` of 49 bytes, which `RedirectReceiver` refuses (`InvalidRelayState`,
  B-9; K-4). The `RelayState` of its `LogoutRequest` is 24 bytes.
- Realm `idp` echoes the `RelayState` it received: 16, 17 and 80 bytes intact, in its forms and in its query string;
  when none was received, none is sent. Keycloak never sent an empty `RelayState`.
- A space in a signed `RelayState`, written `%20` by `RedirectSender` and `+` by hand: both verified and decoded to a
  space, echoed as `a b` in the form.

**Escaping**: every query string Keycloak wrote is in uppercase hexadecimal, its parameters in the order `SAMLRequest`
or `SAMLResponse`, `RelayState`, `SigAlg`, `Signature`, nothing else; a space is `+` and a `~` is left as it is: the
`RelayState` of 80 bytes this package sent came back from realm `idp` as `bindings+~+80+bytes+0123...` (K-8).

**Forms**: the base64 of every form, the response's and the logout response's, on one line, never wrapped; the fields
`SAMLResponse`, then `RelayState` when there is one.

## 5. Measurements

`../measure.php` on the captures of `tests/Fixture/real/`, 1 October 2026 (section 2 has the command):

| Query string | Bytes | Parameters | SigAlg | Escapes | RelayState, bytes | Signature, bytes | Inflated, bytes |
|---|---|---|---|---|---|---|---|
| `keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt` | 993 | SAMLResponse, RelayState, SigAlg, Signature | rsa-sha256 | 32, uppercase; 4 `+`, 0 `%7E` | 80 | 256 | 546 |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-long-relaystate-refused-query-2026-10-01.txt` | 1 124 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 33, uppercase; 0 `+`, 0 `%7E` | 122 | 256 | not read: B-9 refuses it before inflating |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-query-2026-10-01.txt` | 1 096 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 39, uppercase; 0 `+`, 0 `%7E` | 78 | 256 | 704 |
| `keycloak-26.7.4-sp-authnrequest-to-bindings-redirect-binding-refused-query-2026-10-01.txt` | 1 100 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 41, uppercase; 0 `+`, 0 `%7E` | 78 | 256 | 708 |
| `keycloak-26.7.4-sp-authnrequest-unsigned-refused-query-2026-10-01.txt` | 626 | SAMLRequest, RelayState | none | 18, uppercase; 0 `+`, 0 `%7E` | 78 | none | 714 |
| `keycloak-26.7.4-sp-logoutrequest-to-bindings-query-2026-10-01.txt` | 960 | SAMLRequest, RelayState, SigAlg, Signature | rsa-sha256 | 32, uppercase; 0 `+`, 0 `%7E` | 24 | 256 | 583 |
| `keycloak-26.7.4-sp-logoutrequest-unsigned-refused-query-2026-10-01.txt` | 580 | SAMLRequest, RelayState | none | 26, uppercase; 0 `+`, 0 `%7E` | 24 | none | 639 |

| Form, the body a browser posts | Bytes | Fields | Message, base64 characters | Line breaks | RelayState, bytes |
|---|---|---|---|---|---|
| `keycloak-26.7.4-idp-logoutresponse-form-2026-10-01.txt` | 3 697 | SAMLResponse, RelayState | 3 624 | none | 24 |
| `keycloak-26.7.4-idp-logoutresponse-to-bindings-form-2026-10-01.txt` | 3 672 | SAMLResponse, RelayState | 3 604 | none | 17 |
| `keycloak-26.7.4-idp-response-form-2026-10-01.txt` | 7 751 | SAMLResponse, RelayState | 7 596 | none | 78 |
| `keycloak-26.7.4-idp-response-to-bindings-form-2026-10-01.txt` | 7 657 | SAMLResponse, RelayState | 7 564 | none | 16 |

The URLs this package sent realm `idp` in the run measure 978 to 1 024 bytes of query string for an `AuthnRequest`
signed under RSA-SHA256 with a `RelayState` of up to 16 bytes. Against the bounds of section 7 of the specification:
query strings of 580 to 1 124 bytes under `maxQueryStringBytes` 8 192, about a seventh of it; messages of 546 to 714
bytes inflated under `maxInflatedBytes` 65 536; form values of 3 604 to 7 596 characters under `maxFormValueBytes`
1 572 864; every `Signature` of 256 bytes, an RSA-2048 key, its text of 344 characters under 1 368; `RelayState` of 16 to
80 bytes, and 122 bytes from a client whose internal ID is not a UUID (K-4).

## 6. Findings

No genuine message the judge needed was refused by either side once Keycloak's console had the two settings of
section 1, and no rule of the specification had to change for the exchange. What was measured, against sections 4, 6,
7, 8 and 12 of the specification, numbered K-n to stay apart from SimpleSAMLphp's F-n and `saml2-model`'s numbers:

- **K-1. Keycloak's importer ties the three bindings of the broker together.** `saml2-model`'s finding 17, measured again
  on this package's identity provider metadata: import-config sets `postBindingAuthnRequest`, `postBindingResponse` and
  `postBindingLogout` to `false` for a single sign-on service listed for HTTP-Redirect alone, to `true` for one listed
  for HTTP-Redirect then HTTP-POST; it carries `WantAuthnRequestsSigned="true"` to `wantAuthnRequestsSigned`, under
  which the broker signs its `AuthnRequest` and its `LogoutRequest` and publishes its key (`saml2-model`'s finding 18).
  So the importer turns the HTTP-Redirect bindings on from the metadata, and only all of them together.
- **K-2. As imported for HTTP-Redirect, the broker asks for its response over HTTP-Redirect.** Its `AuthnRequest`
  carries `ProtocolBinding` HTTP-Redirect: `RedirectReceiver` verified its signature, and the model refused it
  (`Unsupported`, model.md section 8, `saml2-model`'s finding 1, decided there on 30 September 2026). The rule stands:
  the response cannot travel over HTTP-Redirect (Profiles §4.1.2). With "HTTP-POST binding response" switched on by
  hand, the broker's requests stay on HTTP-Redirect and ask for the response over HTTP-POST. For `heidi/saml`
  (model.md §6.9, section 6.8 of the specification): its identity provider's metadata lists HTTP-POST next to
  HTTP-Redirect, so that a broker configured by Keycloak's importer posts everything; a Keycloak broker sends this
  package a query string only when its administrator sets that switch, and then signed, since the metadata says
  `WantAuthnRequestsSigned`.
- **K-3. The broker's query strings are what section 6.1 reads.** `SAMLRequest`, `RelayState`, `SigAlg`, `Signature`,
  in that order and nothing else, RSA-SHA256, uppercase hexadecimal, base64 padded, raw DEFLATE, a `Signature` of 256
  bytes, the key of realm `sp` in the broker's metadata; the `AuthnRequest` and the `LogoutRequest` verified by
  `RedirectReceiver` and accepted through the binding's authentication. Its `AuthnRequest` names its assertion consumer
  service by URL, which the model resolves to the HTTP-POST one of the three the metadata lists at one `Location`
  (index 2, the HTTP-Redirect one being the default there, `saml2-model`'s finding 9).
- **K-4. The broker's `RelayState` is 78 bytes, and longer for a client whose ID is not a UUID.** Keycloak keeps the SAML
  broker's state short on purpose, 2 bytes under the bound of SAML Bindings §3.4.3, but writes the base64url of the
  `client_id` where the client's internal ID is not a UUID, which a realm imported with such IDs holds: 122 bytes for a
  `client_id` of 49 bytes, refused by `RedirectReceiver` (`InvalidRelayState`, B-9), kept as
  `keycloak-26.7.4-sp-authnrequest-to-bindings-long-relaystate-refused-query-2026-10-01.txt`. Any `client_id` of 19
  bytes or more under such an ID goes over 80 bytes. SAML Bindings §3.4.3 says the value "MUST NOT exceed 80 bytes in
  length": the producer is wrong and the rule stands (section 9.4), with SimpleSAMLphp's long `ReturnTo` (F-5) the
  second producer named under the open item of section 12.
- **K-5. The broker verifies the query string of a `LogoutResponse`.** Under `validateSignature`, every change after
  signing is refused, and so is the response stripped of `Signature` and `SigAlg`, "Invalid signature in response from
  identity provider.", HTTP 400; the genuine one closes realm `sp`'s session. The broker's logout survives the refused
  probes.
- **K-6. Realm `idp` verifies the octets of SAML Bindings §3.4.4.1 as received.** Under "Client signature required", every
  `AuthnRequest` and `LogoutRequest` changed after signing, or stripped of its signature, is refused, "Invalid
  requester", HTTP 400; its genuine twin is accepted. Its verifier builds the octets from the values still
  percent-encoded, `SAMLRequest` or `SAMLResponse`, then `RelayState` when present, then `SigAlg`
  (`SamlProtocolUtils.verifyRedirectSignature()` reads `getQueryParameters(false)`), as B-2 does.
- **K-7. The `SigAlg` realm `idp` accepts: not RSA-SHA384.** It accepts RSA-SHA256, RSA-SHA512, RSASSA-PSS with SHA-256
  and with SHA-512 (measured on PHP 8.5, whose build has them) and RSA-SHA1; it refuses RSA-SHA384 and RSASSA-PSS with
  SHA-384, which Keycloak's `SignatureAlgorithm` does not list, the URI of RSA PKCS#1 v1.5 encryption, RSA-SHA224 and an
  unknown URI: no default algorithm. This package signs under the algorithm of the consumer's `Signing`, RSA-SHA256 by
  default, which Keycloak sends and accepts: a `Signing` under RSA-SHA384 is refused by Keycloak, one under RSA-SHA512 is
  not. Keycloak accepts RSA-SHA1, which this package refuses (B-3): a Keycloak client or broker set to sign under
  `RSA_SHA1` would be refused here, a case for sub-spikes 9c and 9d (section 12), never an option.
- **K-8. Keycloak escapes a space as `+` and leaves `~` alone.** Its query strings carry uppercase hexadecimal; the
  `RelayState` `bindings ~ 80 bytes ...` came back as `bindings+~+80+bytes+...`, verified by `RedirectReceiver` over the
  octets as received and decoded to what was sent (B-2, B-8). It decodes this package's `%20` and a `+` alike. Neither
  differs from what B-8 reads; this package's RFC 3986 escaping, `%20` and `~`, is read by Keycloak as it is.
- **K-9. Keycloak's `LogoutResponse` over HTTP-Redirect, obtained.** Under its client's default, "Force POST binding",
  realm `idp` answers a logout over HTTP-POST, signed in its XML, whatever the binding of the `LogoutRequest`, which is
  why no capture had observed one. With the setting off, and the redirect logout URL the converter draws from metadata
  listing the single logout service for HTTP-Redirect, it answers a `LogoutRequest` received over HTTP-Redirect over
  HTTP-Redirect: `SAMLResponse`, `RelayState`, `SigAlg` RSA-SHA256 and `Signature`, the query string signed under
  `saml.server.signature`, accepted by `RedirectReceiver` and the model (`Authentication::Binding`, `Success`), kept as
  `keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt`. The login response stays over HTTP-POST, as the
  `AuthnRequest` asks.
- **K-10. No empty `RelayState`, no wrapped form.** Realm `idp` echoes the `RelayState` it received and sends none when
  it received none; the broker always sends its state. Its forms carry the base64 on one line, 3 604 to 7 596
  characters. B-9's refusal of an empty `RelayState` (section 12, decided on 1 October 2026) stands measured against
  Keycloak as against SimpleSAMLphp.
- **K-11. Under its defaults the broker signs nothing, over HTTP-Redirect too.** `saml2-model`'s findings 1 and 2 seen
  through the binding: between Keycloak's two realms, the broker's `AuthnRequest` and `LogoutRequest` carry no `SigAlg`
  and no `Signature`; `RedirectReceiver` reads them and the model refuses both (`SignatureRequired`, M-3: realm `idp`'s
  metadata says `WantAuthnRequestsSigned="true"` and the broker's publishes no key), kept as fixtures refused. Realm
  `idp` takes them only because its client in `realms/idp.json` does not require a signature.
- **K-12. Keycloak reads the metadata of this package's roles as the model writes them.** Signed, `KeyInfo` left out of
  every message: the broker accepted this package's response, its assertion signed, and verified its `LogoutResponse`
  (K-5), and realm `idp` verified its requests (K-6), under the certificates its importers drew from the metadata. That
  the broker's acceptance of a response rests on its XML signature is `saml2-model`'s control over HTTP-POST (its
  finding 21), not played again here.

`RealDocumentsTest` reads every capture of this run with the receivers of this package and validates it with the model
under a clock frozen at its capture; `tests/Fixture/real/README.md` lists them.
