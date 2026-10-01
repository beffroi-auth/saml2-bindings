# Adversarial fixtures

The `adversarial-*` files of this directory and of `../behaviour/` are the attempts of the adversarial pass of section
9.8 of `spec/bindings.md` (story #10): each row of section 3 attacked with query strings and forms the corpus of 9.2 and
9.3 does not list, every attempt a file whatever its outcome, `adversarial-<attempt>-refused.txt` here and
`adversarial-<attempt>-accepted.txt` in `../behaviour/`. `tests/Unit/AdversarialTest.php` asserts each, refused with the
exception and the message it got, or accepted with what validation returned, and fails when an attempt of the builder
is asserted by no case or under the other outcome.

A query string is written as the consumer reads it from `QUERY_STRING`, without its `?`, no final line feed; a form as
the `application/x-www-form-urlencoded` body a browser posts, which the test gives to PHP's own parser, the one behind
the fields a consumer gives `PostReceiver` (section 6.8). They are written by `tests/Support/AdversarialQueryBuilder.php`,
never by hand, each a variant of one valid query string or form with the change its name says, signed with the test
keys of `../keys/` wherever the attack needs a valid signature, or a real capture of `../real/` with one change. From the
root of the repository, after `castor install`:

```
docker run --rm -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
    php -r 'require "vendor/autoload.php"; Beffroi\Saml2\Bindings\Tests\Support\AdversarialQueryBuilder::write("tests/Fixture");'
```

RSA PKCS#1 v1.5 signatures are deterministic, so the command writes the committed bytes again, and the adversarial test
compares what the builder writes with every committed file. Run on 1 October 2026 in the phpqa image, PHP 8.5.10; every
attempt has the same outcome on PHP 8.4.25.

The messages are those of `tests/Unit/ReceptionFixtures.php`: the `AuthnRequest` of `https://sp.example.com/saml` to
`https://idp.example.com/saml/sso`, issued at `2026-10-01T12:00:00Z`, signed over the query string with the `sp` key,
its `RelayState` `state` unless the attempt says otherwise; the `LogoutRequest` of the identity provider, signed with
`idp`; the `LogoutResponse` of the service provider, signed with `sp`; the response of the identity provider, its
assertion signed in its XML. The forged `AuthnRequest` is the same request under the ID
`_f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0`, slipped next to the signed one: the ID validation returns says which was
read, and no accepted attempt returns it. A real capture changed is validated as `tests/Unit/RealDocumentsTest.php`
validates the capture it comes from.

| Group | Attempts | Refused | Accepted |
|---|---|---|---|
| Names other than the six as written (`name-`): a second percent-encoding (`SAML%2552equest`), a NUL after, inside or alone, an overlong or invalid UTF-8 sequence, another case, a Cyrillic or full-width letter, a space or a tab before or after, `[]`, `[0]`, `.` and an escaped `=` after; next to the signed query string and alone | 33 | 7 | 26 |
| Separators (`separator-`): `;`, `&amp;` before one parameter and everywhere, `?` and `#` in a value, the leading `?` kept, empty segments up to the bound and sixty thousand under the ceiling, 1 001 other parameters first | 16 | 7 | 9 |
| Values (`value-`): a space, a NUL, a second percent-encoding in the message, `Signature` and `SAMLEncoding` | 10 | 10 | 0 |
| Signature confusion (`confusion-`): one parameter twice in two spellings, the CVE's two message parameters with the second under a name PHP's parser reads as `SAMLRequest`, the forged message under a longer name or inside another value first, `RelayState` folded into the message, each part spelled again after signing, `SigAlg` of SHA-512 over a SHA-256 signature | 13 | 6 | 7 |
| `SAMLEncoding` (`encoding-`): every byte escaped, lowercase hexadecimal, unescaped, first of a signed query string, over a message not deflated, in upper case, with a trailing slash, under a name in lower case | 8 | 3 | 5 |
| `SigAlg` (`sig-alg-`): case of the fragment, scheme and host, `https`, a trailing slash, whitespace and NUL around it, a second percent-encoding, SHA-256 under the SHA-1 namespace, RSA-SHA224, RSA PKCS#1 v1.5 encryption; the listed URI escaped otherwise, signed as sent | 18 | 15 | 3 |
| Base64 (`base64-`): padding in the middle of the message and of `Signature`, CR LF in the message, a set unused bit and the URL-safe alphabet in `Signature`; the message unescaped and every character escaped, signed as sent | 7 | 5 | 2 |
| DEFLATE (`deflate-`): stored blocks, fixed codes, 500 and 5 000 empty stored blocks first, the high bit after the final block set; two final blocks, an empty block after the final one, a preset dictionary through the zlib wrapper (FDICT) and against raw DEFLATE, a reserved block type, a stored length and its complement apart, a flush without a final block, an empty stream | 14 | 8 | 6 |
| `RelayState` (`relay-state-`): CR LF, NUL, HTML, a URL, invalid and unescaped UTF-8, whitespace at its ends, a second percent-encoding, 80 bytes written in 240 characters or as 80 `+`, 81 `+`, 80 and 81 bytes of characters of several bytes | 16 | 2 | 14 |
| Forms (`form-`): `[0]`, `[a][b]` and escaped brackets after a field name, names PHP's parser rewrites, `SAMLEncoding`, `Signature[]`, `sigalg`, an empty `SigAlg`, the message field twice, base64 wrapped by CR alone, every three characters and at both ends, a form feed, a vertical tab, a no-break space or a NUL in it, its padding in the middle, encoded twice, its `+` unescaped, a `RelayState` holding CR LF, NUL or HTML, at and over 80 bytes, the message at `maxFormValueBytes`, one over, and over by its line breaks | 33 | 18 | 15 |
| Bounds (`bound-`): the query string at the ceiling of `maxQueryStringBytes` and one over, `Signature` of 1 024 bytes in 1 368 characters and written in 4 104, of 256 bytes | 5 | 4 | 1 |
| Real captures (`real-`): SimpleSAMLphp's and Keycloak's signed `AuthnRequest` and `LogoutResponse`, one character of each part escaped and changed, their parameters reversed, `SAMLEncoding` added; their response forms, one character of the message or of `RelayState` changed | 44 | 30 | 14 |
| **Written by the builder** | **217** | **115** | **102** |

Thirty-two more attempts are calls, not inputs, each a named case of a data provider of `AdversarialTest`, named as a
file would be: fields no parser of a form gives (an integer, `null`, `true` or a `Stringable` where a string is read, a
list without names, `SigAlg` holding `null`), 6 refused, and fields named by integers, 1 accepted; a received message
serialized and one unserialized from crafted bytes, 2 refused, and a `Reception` assembled by a closure bound to its
scope, 1 accepted; Destinations whose query holds names the receiver skips, values it never decodes, or whose host is in
Unicode, in punycode or percent-encoded, sent by `RedirectSender` and read back by the receiver, 19 accepted, two whose
query names `SAMLResponse` in lowercase hexadecimal or `SAMLRequest` twice, refused before the key is called, and one
posted by `PostSender` with `SAMLRequest` in the query of its action, accepted. In all, 249 attempts, 125 refused and 124
accepted.
