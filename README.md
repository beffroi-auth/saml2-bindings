# beffroi/saml2-bindings

Part of [beffroi/framework](https://github.com/beffroi-auth/beffroi), developed in `src/saml2-bindings` of that monorepo; this repository is
its read-only split. Issues and pull requests go to the monorepo.

The two browser bindings of SAML 2.0 for PHP, HTTP-Redirect and HTTP-POST, on
[`beffroi/saml2-model`](https://github.com/beffroi-auth/saml2-model) and
[`beffroi/xml-security`](https://github.com/beffroi-auth/xml-security): a query string or a form decoded into the
document the model reads, the detached signature of HTTP-Redirect verified over the octets the sender signed and
nothing else, and a message the model writes turned into a URL or a form's fields. It works on strings and arrays,
never on an HTTP request, and reads no SAML element: which message it expects is the method you call.

[`spec/bindings.md`](spec/bindings.md) is the law of the package: the code conforms to it, or the document changes
first. This file is its short version.

The package requires PHP 8.4 or later, `ext-zlib`, `beffroi/saml2-model` and `beffroi/xml-security`, and nothing
else. None of the three has a tag yet: they are required at the maintenance branch.

```json
{
    "require": {"beffroi/saml2-bindings": "0.0.x-dev"},
    "minimum-stability": "dev",
    "prefer-stable": true
}
```

## Receiving over HTTP-Redirect, identity provider side

```php
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;

$loader = SamlLoader::create();                        // one loader for the receiver and the validator (M-14)
$received = new RedirectReceiver($loader)->authnRequest($queryString);   // the raw QUERY_STRING, as it arrived
// $received->request->issuer chooses the peer, and nothing else
$sp = $peers->serviceProvider($received->request->issuer);   // your store of the metadata you read

$accepted = $received->validate(
    new AuthnRequestValidator($loader, $clock),
    $sp,
    $self,                                             // your IdentityProvider
    'https://idp.example.com/saml/sso',                // your SingleSignOnService, from your configuration
);
$accepted->authentication;    // Authentication::Binding when the query string was signed and its signature held
$received->relayState;        // opaque, never given to the model: echo it in your answer
```

`authnRequest()` reads the parameters before it decodes anything: exactly one message, each parameter of the binding
once under its literal name, `SigAlg` on the closed list of `xml-security`, every input bounded, raw DEFLATE inflated
under its bound. `validate()` verifies the signature over `SAMLRequest`, `RelayState` and `SigAlg` as they arrived,
in that order, under the keys of the service provider's metadata, then hands the model a message the binding
authenticated; an unsigned one goes to the model's `validate()`, which refuses it when either party's metadata wants
it signed. `logoutMessage()` reads a `LogoutRequest` or a `LogoutResponse` at a single logout service, whose
`validate()` refuses either unsigned.
Every refusal is a `BindingRefused` naming its rule, or the refusal of `xml-security` or the model as it is: all
extend `RefusedXml`.

## Receiving over HTTP-POST, service provider side

```php
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Model\Validation\{ExpectedResponse, ResponseValidator};

$received = new PostReceiver($loader)->response($fields);   // the fields your parser decoded from the body
$idp = $peers->identityProvider($received->response->issuer);

$accepted = $received->validate(
    new ResponseValidator($loader, $clock, $replayGuard),
    $idp,
    ExpectedResponse::toRequest($requestId, 'https://sp.example.com/saml/acs', 'https://sp.example.com/saml'),
);
$accepted->assertion;         // read from what the XML signatures cover
```

Over HTTP-POST the message carries its XML signatures, which the model verifies; `SigAlg` or `Signature` in a form is
refused. `authnRequest()` and `logoutMessage()` read the other messages a form carries.

## Sending

```php
use Beffroi\Saml2\Bindings\{PostSender, RedirectSender};
use Beffroi\Saml2\Model\Writing\{SignedParts, Signing};
use Beffroi\Xml\Dsig\PrivateKey;

$signing = new Signing(PrivateKey::fromPem($keyPem));  // or any Dsig SigningKeyInterface, a key management service's

$url = new RedirectSender()->authnRequest($authnRequest, $signing, $relayState);   // answer 302 or 303 to $url
$url = new RedirectSender()->logoutRequest($logoutRequest, $signing);             // a logout message is always signed

$form = new PostSender()->response($response, $signing, SignedParts::Assertion, $relayState);
$form->action;                // the response's Destination
$form->fields;                // SAMLResponse, then RelayState: as they go on the wire, not escaped for HTML
```

The senders call the model's writers themselves: over HTTP-Redirect with no XML signature, the query string signed
in the order of the binding, uppercase hexadecimal; over HTTP-POST signed in XML. What a sender writes, the package's
receiver reads under the same `BindingLimits`: a `RelayState` or a `Destination` the receiver would refuse is an
`\InvalidArgumentException` before the key is called, a message over a bound a `LimitExceeded`. No method sends a
response over HTTP-Redirect.

## What your application holds

The package carries one message across one binding against what you state; the consumer it is written for is
`beffroi/saml`, and section 6.8 of the specification is its contract:

- the raw query string, `QUERY_STRING`, never a normalised one (`Request::getQueryString()`) nor the parsed query;
- the fields of an `application/x-www-form-urlencoded` body, any other content type refused before the call;
- `$receivedAt`, the URL of your endpoint from your configuration, never rebuilt from the request's `Host`;
- `validateAuthenticatedByBinding()` never called by you: your PHPStan configuration bans it, and bans
  `Closure::bind()`, `Closure::bindTo()`, `Closure::call()` and Reflection on `Beffroi\Saml2\Bindings\Internal\`;
- the `RelayState` you generate, an unguessable reference of at most 80 bytes to state you keep, and the one you
  received, echoed exactly in your answer;
- the page that posts the form: the `action` and every field escaped for HTML, submitted by a script your content
  security policy allows, a button inside `noscript`, and the caching headers of the binding.

## The invariants

Each is code, never an option, and has its tests; `TraceabilityTest` fails when one is cited by no test.

| | |
|---|---|
| B-1 | One message parameter, `SAMLRequest` or `SAMLResponse`; every parameter the binding reads at most once, under its literal name, and no name PHP's parser of a query string reads as one of them. |
| B-2 | The HTTP-Redirect signature is verified over `SAMLRequest` or `SAMLResponse`, `RelayState` and `SigAlg`, in that order, as received, never re-encoded. |
| B-3 | `Signature` and `SigAlg` together; `SigAlg` on the closed list of `xml-security`, SHA-1 and DSA refused. |
| B-4 | The keys are those of the peer's metadata. |
| B-5 | The model hears that the binding authenticated a message only from this package, only after the signature held over the very input the message was decoded from. |
| B-6 | No XML signature travels over HTTP-Redirect, either way. |
| B-7 | Every input is bounded before it is decoded; DEFLATE is bounded while it inflates. |
| B-8 | One lexical form per value: strict percent-encoding, canonical base64, raw DEFLATE complete and alone. |
| B-9 | `RelayState` is opaque, at most 1 024 bytes, never empty, returned to the consumer, never given to the model. |
| B-10 | What arrived is loaded as it arrived; what is sent is serialized once. |
| B-11 | A refusal names its rule and never carries a value of the input. |
| B-12 | No response over HTTP-Redirect; every logout message sent is signed. |
| B-13 | No HTTP object, no superglobal, no header, no HTML. |

Two deviations from SAML Bindings are named in section 8 of the specification, neither a switch: RSA-SHA1 and
DSA-SHA1, which §3.4.4.1 requires, are refused; a `RelayState` of up to 1 024 bytes is read and sent where §3.4.3 and
§3.5.3 say 80, since real service providers send longer ones and the responder must echo what it received.

## Development

From the root of the monorepo, which holds the toolchain of every package:

```bash
composer install
castor phpunit -- --testsuite saml2-bindings     # PHPUnit 13 with coverage, this package's suite
castor prepare-pr                                # Mago lint and format, Rector, PHPStan, Deptrac
castor phpstan                                   # this package under .ci-tools/phpstan-saml2-bindings.neon: level max, no baseline, the bans of section 8
castor infect --strict                           # Infection on the files of section 9, no escaped mutant allowed
castor infect --diff                             # the lines changed since origin/HEAD; without either, the whole source
castor saml2-bindings-oracle                     # every signed URL the sender writes, verified by OpenSSL, its message inflated by Python
castor saml2-bindings-simplesamlphp              # the judge of section 9.5: SimpleSAMLphp as identity provider and service provider, both ways
castor saml2-bindings-keycloak                   # Keycloak as identity provider and broker, both ways, by hand
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available. The CI runs this package's
suite on PHP 8.5 and on PHP 8.4.

## Security

See the [security policy](https://github.com/beffroi-auth/beffroi/blob/0.0.x/SECURITY.md) of the monorepo: private reporting, an advisory and a CVE for
every fix.

## License

MIT, see the [LICENSE](https://github.com/beffroi-auth/beffroi/blob/0.0.x/LICENSE) of the monorepo.
