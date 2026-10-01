# beffroi-php/saml2-bindings

The two browser bindings of SAML 2.0 for PHP, HTTP-Redirect and HTTP-POST, on
[`beffroi-php/saml2-model`](https://github.com/beffroi-php/saml2-model) and
[`beffroi-php/xml-security`](https://github.com/beffroi-php/xml-security): a query string or a form decoded into the
document the model reads, the detached signature of HTTP-Redirect verified over the octets the sender signed and
nothing else, and a message the model writes turned into a URL or a form's fields. It works on strings and arrays,
never on an HTTP request, and reads no SAML element.

[`spec/bindings.md`](spec/bindings.md) is the law of the package: the code conforms to it, or the document changes
first. This file is its short version. Nothing is built yet; the specification is the whole repository until the
first story lands.

## What it guarantees

Each is code, never an option, and has its tests (section 4 of the specification).

| | |
|---|---|
| B-1 | One message parameter, `SAMLRequest` or `SAMLResponse`; every parameter the binding reads at most once, under its literal name. |
| B-2 | The HTTP-Redirect signature is verified over `SAMLRequest` or `SAMLResponse`, `RelayState` and `SigAlg`, in that order, as received, never re-encoded. |
| B-3 | `Signature` and `SigAlg` together; `SigAlg` on the closed list of `xml-security`, SHA-1 and DSA refused. |
| B-4 | The keys are those of the peer's metadata. |
| B-5 | The model hears that the binding authenticated a message only from this package, only after the signature held. |
| B-6 | No XML signature travels over HTTP-Redirect, either way. |
| B-7 | Every input is bounded before it is decoded; DEFLATE is bounded while it inflates. |
| B-8 | One lexical form per value: strict percent-encoding, canonical base64, raw DEFLATE complete and alone. |
| B-9 | `RelayState` is opaque, at most 80 bytes, returned to the consumer, never given to the model. |
| B-10 | What arrived is loaded as it arrived; what is sent is serialized once. |
| B-11 | A refusal names its rule and never carries a value of the input. |
| B-12 | No response over HTTP-Redirect; every logout message sent is signed. |
| B-13 | No HTTP object, no superglobal, no header, no HTML. |

## Security

Report privately through the security advisories of this repository. Every fix ships with an advisory and a CVE
(specification, section 10).

## License

MIT.
