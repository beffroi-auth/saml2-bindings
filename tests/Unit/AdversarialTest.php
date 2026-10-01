<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\AdversarialQueryBuilder;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Xml\Core\Exception\EncodingRefused;
use Beffroi\Xml\Core\Exception\InvalidId;
use Beffroi\Xml\Core\Exception\MalformedXml;
use Beffroi\Xml\Dsig\Exception\DigestMismatch;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Closure;
use DateTimeImmutable;
use Exception;
use InvalidArgumentException;
use function ksort;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function serialize;
use function sprintf;
use function str_pad;
use function str_repeat;
use function str_replace;
use function str_starts_with;
use function strlen;
use Stringable;
use Throwable;
use TypeError;
use function unserialize;

/**
 * Section 9.8, the adversarial pass of 1 October 2026 (story #10): each row of section 3 attacked with query strings and
 * forms the corpus of 9.2 and 9.3 does not list, every attempt a fixture of tests/Support/AdversarialQueryBuilder
 * whatever its outcome, asserted with the exception and the message it got, or accepted with what validation returned;
 * and, where the attempt is a call and not an input, a named case of a data provider, named after its outcome as a
 * fixture would be. An attempt accepted is the consumer's one path, received then validated: over a signed query
 * string, Authentication::Binding and the ID of the message the signature covers, never the forged one slipped next
 * to it. None bypassed a rule of section 4. Two classes of attempt are accepted by the rules as they stand and are
 * open questions of section 12: names PHP's own parser of a query string reads as one of the six of B-1 while the
 * package does not, and a received message assembled by code that leaves the scope PHP gives it (Closure::bind).
 * SAML Bindings §3.4.4.1, §3.5.4.
 *
 * @phpstan-type Message 'an AuthnRequest'|'a LogoutRequest'|'a LogoutResponse'
 */
final class AdversarialTest extends TestCase
{
    use SendingFixtures;

    /**
     * The ID of the LogoutResponse of ReceptionFixtures.
     */
    private const string LOGOUT_RESPONSE_ID = '_6e2b1f8d0c4a5b3f9e7d2c1b0a9f8e7d6c5b4a3f';

    /**
     * The base64 of the response of ReceptionFixtures on one line, in bytes, the bound of the form attempts at
     * maxFormValueBytes.
     */
    private const int RESPONSE_BASE64_BYTES = 3_892;

    private const string NEITHER = 'The query string carries neither SAMLRequest nor SAMLResponse (B-1).';

    private const string HALF_A_SIGNATURE = 'SigAlg and Signature are both present or both absent (B-3).';

    private const string TWICE = 'A parameter of the binding appears more than once (B-1).';

    private const string NOT_BASE64 = 'A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).';

    private const string NOT_RAW_DEFLATE = 'The message is not raw DEFLATE (B-8).';

    private const string BYTES_AFTER_THE_FINAL_BLOCK = 'Bytes follow the final block of the DEFLATE stream (B-8).';

    private const string NO_FINAL_BLOCK = 'The DEFLATE stream ends before its final block (B-8).';

    private const string OFF_THE_LIST = 'The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).';

    private const string ANOTHER_ENCODING = 'A SAMLEncoding other than DEFLATE is refused (section 8).';

    private const string NO_KEY_VERIFIES = 'No trusted key verifies the detached signature (D-7, D-8).';

    private const string RELAY_STATE_OVER_80_BYTES = 'The RelayState is longer than 80 bytes (B-9).';

    private const string NOT_A_STRING = 'A field of the binding is not a string, an array for instance (B-1).';

    private const string FORM_WITHOUT_MESSAGE = 'The form carries neither SAMLRequest nor SAMLResponse (B-1).';

    private const string SIGNATURE_IN_A_FORM = 'SigAlg or Signature in a form is refused: HTTP-POST carries no detached signature (section 8).';

    private const string SIGNATURE_REQUIRED = 'The message carries no ds:Signature, which the profile requires (M-2).';

    /**
     * Section 9.8, section 9.7: every attempt on disk is what the builder writes, byte for byte, so that the command of
     * tests/Fixture/hostile/adversarial-README.md writes them again.
     */
    #[Test]
    public function itBuildsTheCommittedFixtures(): void
    {
        // When
        $fixtures = AdversarialQueryBuilder::fixtures();

        // Then
        foreach ($fixtures as $path => $bytes) {
            static::assertSame(self::fixture($path), $bytes, $path);
        }
    }

    /**
     * Section 9.8: every attempt of the builder is asserted by one case of this class, none left unread, none asserted
     * under the other outcome.
     */
    #[Test]
    public function itAssertsEveryAttempt(): void
    {
        // Given
        $asserted = [];
        foreach ([
            self::provideRefusedQueryStrings(),
            self::provideRefusedForms(),
            self::provideRefusedRealCaptures(),
        ] as $cases) {
            foreach ($cases as $case) {
                $asserted[AdversarialQueryBuilder::refused($case[0])] = true;
            }
        }
        foreach ([
            self::provideAcceptedQueryStrings(),
            self::provideAcceptedForms(),
            self::provideAcceptedRealCaptures(),
        ] as $cases) {
            foreach ($cases as $case) {
                $asserted[AdversarialQueryBuilder::accepted($case[0])] = true;
            }
        }
        ksort($asserted);

        // When
        $written = [];
        foreach (AdversarialQueryBuilder::fixtures() as $path => $bytes) {
            $written[$path] = $bytes !== '';
        }
        ksort($written);

        // Then
        static::assertSame($written, $asserted);
    }

    /**
     * Section 9.8, section 3 rows 1 to 4, 7, 8 and 10, B-1 to B-3, B-7 to B-9: every query string attempt that is
     * refused, received then validated as the consumer does, with the exception and the message it got.
     *
     * @param class-string<Throwable> $exception
     * @param Message                 $message
     */
    #[Test]
    #[DataProvider('provideRefusedQueryStrings')]
    public function itRefusesAQueryStringAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $text,
        string $message = 'an AuthnRequest',
        int $maxQueryStringBytes = 8_192,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($text);

        // When
        $this->receiveAndValidate(
            $message,
            self::fixture(AdversarialQueryBuilder::refused($attempt)),
            $maxQueryStringBytes,
        );
    }

    /**
     * @return iterable<string, array{0: string, 1: class-string<Throwable>, 2: string, 3?: Message, 4?: int}>
     */
    public static function provideRefusedQueryStrings(): iterable
    {
        // Section 3 rows 1 and 2, B-1: names other than the six as written; those PHP's parser reads as one of them among them.
        yield 'name double percent encoded saml request alone' => [
            'name-double-percent-encoded-saml-request-alone',
            MalformedParameters::class,
            self::NEITHER,
        ];
        yield 'name double percent encoded sig alg in place of sig alg' => [
            'name-double-percent-encoded-sig-alg-in-place-of-sig-alg',
            MalformedParameters::class,
            self::HALF_A_SIGNATURE,
        ];
        yield 'name nul after saml request alone' => [
            'name-nul-after-saml-request-alone',
            MalformedParameters::class,
            self::NEITHER,
        ];
        yield 'name lower case saml request alone' => [
            'name-lower-case-saml-request-alone',
            MalformedParameters::class,
            self::NEITHER,
        ];
        yield 'name lower case sig alg and signature logout request' => [
            'name-lower-case-sig-alg-and-signature-logout-request',
            SignatureRequired::class,
            self::SIGNATURE_REQUIRED,
            'a LogoutRequest',
        ];
        yield 'name cyrillic e in saml request alone' => [
            'name-cyrillic-e-in-saml-request-alone',
            MalformedParameters::class,
            self::NEITHER,
        ];
        yield 'name escaped equals and the message in the name alone' => [
            'name-escaped-equals-and-the-message-in-the-name-alone',
            MalformedParameters::class,
            self::NEITHER,
        ];

        // Section 3 rows 1 to 3, B-1, B-2: separators, and characters of a URL in values.
        yield 'separator semicolon before relay state' => [
            'separator-semicolon-before-relay-state',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'separator semicolon before sig alg' => [
            'separator-semicolon-before-sig-alg',
            MalformedParameters::class,
            self::HALF_A_SIGNATURE,
        ];
        yield 'separator semicolon before signature' => [
            'separator-semicolon-before-signature',
            MalformedParameters::class,
            self::HALF_A_SIGNATURE,
        ];
        yield 'separator ampersand entity before relay state' => [
            'separator-ampersand-entity-before-relay-state',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'separator ampersand entity everywhere logout request' => [
            'separator-ampersand-entity-everywhere-logout-request',
            SignatureRequired::class,
            self::SIGNATURE_REQUIRED,
            'a LogoutRequest',
        ];
        yield 'separator leading question mark kept' => [
            'separator-leading-question-mark-kept',
            MalformedParameters::class,
            self::NEITHER,
        ];
        yield 'separator leading question mark kept message second' => [
            'separator-leading-question-mark-kept-message-second',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];

        // B-8: whitespace, NUL and a second percent-encoding in each value.
        yield 'value space before the message' => [
            'value-space-before-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value space after the message' => [
            'value-space-after-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value nul after the message' => [
            'value-nul-after-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value double percent encoded message' => [
            'value-double-percent-encoded-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value space before the signature' => [
            'value-space-before-the-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value nul after the signature' => [
            'value-nul-after-the-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value double percent encoded signature' => [
            'value-double-percent-encoded-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'value space after saml encoding' => [
            'value-space-after-saml-encoding',
            Unsupported::class,
            self::ANOTHER_ENCODING,
        ];
        yield 'value nul after saml encoding' => [
            'value-nul-after-saml-encoding',
            Unsupported::class,
            self::ANOTHER_ENCODING,
        ];
        yield 'value double percent encoded saml encoding' => [
            'value-double-percent-encoded-saml-encoding',
            Unsupported::class,
            self::ANOTHER_ENCODING,
        ];

        // Section 3 rows 1 and 3, B-1, B-2, B-5: signature confusion beyond CVE-2025-27773.
        yield 'confusion saml request twice in two spellings' => [
            'confusion-saml-request-twice-in-two-spellings',
            MalformedParameters::class,
            self::TWICE,
        ];
        yield 'confusion relay state folded into the message' => [
            'confusion-relay-state-folded-into-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'confusion message escaped again after signing' => [
            'confusion-message-escaped-again-after-signing',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'confusion relay state space written again after signing' => [
            'confusion-relay-state-space-written-again-after-signing',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'confusion sig alg escaped again after signing' => [
            'confusion-sig-alg-escaped-again-after-signing',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'confusion sig alg of sha512 over a signature under sha256' => [
            'confusion-sig-alg-of-sha512-over-a-signature-under-sha256',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];

        // Section 8: SAMLEncoding.
        yield 'encoding deflate over a message not deflated' => [
            'encoding-deflate-over-a-message-not-deflated',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'encoding deflate in upper case' => [
            'encoding-deflate-in-upper-case',
            Unsupported::class,
            self::ANOTHER_ENCODING,
        ];
        yield 'encoding deflate with a trailing slash' => [
            'encoding-deflate-with-a-trailing-slash',
            Unsupported::class,
            self::ANOTHER_ENCODING,
        ];

        // Section 3 row 4, B-3, D-5: SigAlg.
        yield 'sig alg fragment in upper case' => [
            'sig-alg-fragment-in-upper-case',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg scheme in upper case' => [
            'sig-alg-scheme-in-upper-case',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg host in upper case' => [
            'sig-alg-host-in-upper-case',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg https scheme' => ['sig-alg-https-scheme', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg trailing slash' => [
            'sig-alg-trailing-slash',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg space before' => ['sig-alg-space-before', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg space after' => ['sig-alg-space-after', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg tab after' => ['sig-alg-tab-after', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg line feed after' => [
            'sig-alg-line-feed-after',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg no break space after' => [
            'sig-alg-no-break-space-after',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg nul after' => ['sig-alg-nul-after', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg double percent encoded' => [
            'sig-alg-double-percent-encoded',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg sha256 under the namespace of sha1' => [
            'sig-alg-sha256-under-the-namespace-of-sha1',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'sig alg rsa sha224' => ['sig-alg-rsa-sha224', UnknownSignatureAlgorithm::class, self::OFF_THE_LIST];
        yield 'sig alg rsa pkcs1 encryption' => [
            'sig-alg-rsa-pkcs1-encryption',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];

        // B-8: base64.
        yield 'base64 padding in the middle of the message' => [
            'base64-padding-in-the-middle-of-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'base64 padding in the middle of the signature' => [
            'base64-padding-in-the-middle-of-the-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'base64 carriage return and line feed in the message' => [
            'base64-carriage-return-and-line-feed-in-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'base64 unused bit set in the signature' => [
            'base64-unused-bit-set-in-the-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'base64 url safe alphabet in the signature' => [
            'base64-url-safe-alphabet-in-the-signature',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];

        // Section 3 rows 7 and 8, B-7, B-8, RFC 1951: DEFLATE.
        yield 'deflate two final blocks' => [
            'deflate-two-final-blocks',
            MalformedEncoding::class,
            self::BYTES_AFTER_THE_FINAL_BLOCK,
        ];
        yield 'deflate empty final block after the final block' => [
            'deflate-empty-final-block-after-the-final-block',
            MalformedEncoding::class,
            self::BYTES_AFTER_THE_FINAL_BLOCK,
        ];
        yield 'deflate zlib preset dictionary' => [
            'deflate-zlib-preset-dictionary',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'deflate raw against a preset dictionary' => [
            'deflate-raw-against-a-preset-dictionary',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'deflate reserved block type' => [
            'deflate-reserved-block-type',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'deflate stored block length and complement disagree' => [
            'deflate-stored-block-length-and-complement-disagree',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'deflate flushed without a final block' => [
            'deflate-flushed-without-a-final-block',
            MalformedEncoding::class,
            self::NO_FINAL_BLOCK,
        ];
        yield 'deflate empty stream' => ['deflate-empty-stream', MalformedXml::class, 'The input is empty (I-3).'];

        // Section 3 row 10, B-9: RelayState.
        yield 'relay state 81 spaces written plus' => [
            'relay-state-81-spaces-written-plus',
            InvalidRelayState::class,
            self::RELAY_STATE_OVER_80_BYTES,
        ];
        yield 'relay state 81 bytes ending with a character of two bytes' => [
            'relay-state-81-bytes-ending-with-a-character-of-two-bytes',
            InvalidRelayState::class,
            self::RELAY_STATE_OVER_80_BYTES,
        ];

        // Section 7, B-7, D-14: the bounds at and one over their value.
        yield 'bound query string one byte over the ceiling' => [
            'bound-query-string-one-byte-over-the-ceiling',
            LimitExceeded::class,
            'The query string is longer than maxQueryStringBytes, 65536 bytes (B-7).',
            'an AuthnRequest',
            65_536,
        ];
        yield 'bound signature of 1024 bytes in 1368 characters' => [
            'bound-signature-of-1024-bytes-in-1368-characters',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'bound signature of 1368 characters written in 4104' => [
            'bound-signature-of-1368-characters-written-in-4104',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'bound signature of 256 bytes' => [
            'bound-signature-of-256-bytes',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
    }

    /**
     * Section 9.8, section 3 rows 1 to 4, 7, 8 and 10, B-1 to B-3, B-5, B-8, B-9: every query string attempt that is
     * accepted, received then validated as the consumer does: the authentication validation returned, the ID of the
     * message it validated, the one the signature covers, and the RelayState returned.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideAcceptedQueryStrings')]
    public function itAcceptsAQueryStringAttemptAsTheRulesSay(
        string $attempt,
        Authentication $authentication,
        string $id,
        ?string $relayState,
        string $message = 'an AuthnRequest',
        int $maxQueryStringBytes = 8_192,
    ): void {
        // When
        $accepted = $this->receiveAndValidate(
            $message,
            self::fixture(AdversarialQueryBuilder::accepted($attempt)),
            $maxQueryStringBytes,
        );

        // Then
        static::assertSame([$authentication, $id, $relayState], $accepted);
    }

    /**
     * @return iterable<string, array{0: string, 1: Authentication, 2: string, 3: ?string, 4?: Message, 5?: int}>
     */
    public static function provideAcceptedQueryStrings(): iterable
    {
        // Section 3 rows 1 and 2, B-1: names other than the six as written; those PHP's parser reads as one of them among them.
        yield 'name double percent encoded saml request' => [
            'name-double-percent-encoded-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name nul after saml request' => [
            'name-nul-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name nul and a letter after saml request' => [
            'name-nul-and-a-letter-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name nul after relay state' => [
            'name-nul-after-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name nul inside saml request' => [
            'name-nul-inside-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name nul alone' => ['name-nul-alone', Authentication::Binding, self::AUTHN_REQUEST_ID, 'state'];
        yield 'name overlong utf8 e in saml request' => [
            'name-overlong-utf8-e-in-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name overlong utf8 nul after saml request' => [
            'name-overlong-utf8-nul-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name invalid utf8 after saml request' => [
            'name-invalid-utf8-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name lower case saml request' => [
            'name-lower-case-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name upper case relay state' => [
            'name-upper-case-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name lower case sig alg and signature' => [
            'name-lower-case-sig-alg-and-signature',
            Authentication::None,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name cyrillic e in saml request' => [
            'name-cyrillic-e-in-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name cyrillic a in relay state' => [
            'name-cyrillic-a-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name fullwidth s in saml request' => [
            'name-fullwidth-s-in-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name space after saml request written plus' => [
            'name-space-after-saml-request-written-plus',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name space after saml request written escaped' => [
            'name-space-after-saml-request-written-escaped',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name space before saml request written plus' => [
            'name-space-before-saml-request-written-plus',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name space before saml request written escaped' => [
            'name-space-before-saml-request-written-escaped',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name space before saml request written raw' => [
            'name-space-before-saml-request-written-raw',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name tab before saml request' => [
            'name-tab-before-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name brackets after saml request' => [
            'name-brackets-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name escaped brackets after saml request' => [
            'name-escaped-brackets-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name index after relay state' => [
            'name-index-after-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name dot after saml request' => [
            'name-dot-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'name escaped equals after saml request' => [
            'name-escaped-equals-after-saml-request',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 3 rows 1 to 3, B-1, B-2: separators, and characters of a URL in values.
        yield 'separator semicolon and a message in relay state' => [
            'separator-semicolon-and-a-message-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a;SAMLRequest=x',
        ];
        yield 'separator ampersand entity everywhere' => [
            'separator-ampersand-entity-everywhere',
            Authentication::None,
            self::AUTHN_REQUEST_ID,
            null,
        ];
        yield 'separator ampersand entity escaped in relay state' => [
            'separator-ampersand-entity-escaped-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a&amp;b',
        ];
        yield 'separator question mark in relay state' => [
            'separator-question-mark-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a?b',
        ];
        yield 'separator hash in relay state' => [
            'separator-hash-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a#b',
        ];
        yield 'separator hash escaped in relay state' => [
            'separator-hash-escaped-in-relay-state',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a#b',
        ];
        yield 'separator empty segments up to the bound' => [
            'separator-empty-segments-up-to-the-bound',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'separator sixty thousand empty segments under the ceiling' => [
            'separator-sixty-thousand-empty-segments-under-the-ceiling',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
            'an AuthnRequest',
            65_536,
        ];
        yield 'separator a thousand and one other parameters first' => [
            'separator-a-thousand-and-one-other-parameters-first',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 3 rows 1 and 3, B-1, B-2, B-5: signature confusion beyond CVE-2025-27773.
        yield 'confusion signed logout response and a logout request under a space' => [
            'confusion-signed-logout-response-and-a-logout-request-under-a-space',
            Authentication::Binding,
            self::LOGOUT_RESPONSE_ID,
            'state',
            'a LogoutResponse',
        ];
        yield 'confusion signed logout response and a logout request under a nul' => [
            'confusion-signed-logout-response-and-a-logout-request-under-a-nul',
            Authentication::Binding,
            self::LOGOUT_RESPONSE_ID,
            'state',
            'a LogoutResponse',
        ];
        yield 'confusion signed logout response and a logout request under brackets' => [
            'confusion-signed-logout-response-and-a-logout-request-under-brackets',
            Authentication::Binding,
            self::LOGOUT_RESPONSE_ID,
            'state',
            'a LogoutResponse',
        ];
        yield 'confusion forged message under a longer name first' => [
            'confusion-forged-message-under-a-longer-name-first',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'confusion forged message inside another value first' => [
            'confusion-forged-message-inside-another-value-first',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'confusion relay state holding what a decoding parser reads as sig alg' => [
            'confusion-relay-state-holding-what-a-decoding-parser-reads-as-sig-alg',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'a&SigAlg=x',
        ];
        yield 'confusion signature escaped again after signing' => [
            'confusion-signature-escaped-again-after-signing',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 8: SAMLEncoding.
        yield 'encoding deflate every byte escaped' => [
            'encoding-deflate-every-byte-escaped',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'encoding deflate in lower case hexadecimal' => [
            'encoding-deflate-in-lower-case-hexadecimal',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'encoding deflate unescaped' => [
            'encoding-deflate-unescaped',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'encoding deflate first of a signed query string' => [
            'encoding-deflate-first-of-a-signed-query-string',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'encoding name in lower case holding another uri' => [
            'encoding-name-in-lower-case-holding-another-uri',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 3 row 4, B-3, D-5: SigAlg.
        yield 'sig alg in lower case hexadecimal signed as sent' => [
            'sig-alg-in-lower-case-hexadecimal-signed-as-sent',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'sig alg every byte escaped signed as sent' => [
            'sig-alg-every-byte-escaped-signed-as-sent',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'sig alg unescaped but its hash signed as sent' => [
            'sig-alg-unescaped-but-its-hash-signed-as-sent',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // B-8: base64.
        yield 'base64 slash and padding unescaped signed as sent' => [
            'base64-slash-and-padding-unescaped-signed-as-sent',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'base64 every character escaped signed as sent' => [
            'base64-every-character-escaped-signed-as-sent',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 3 rows 7 and 8, B-7, B-8, RFC 1951: DEFLATE.
        yield 'deflate stored blocks' => [
            'deflate-stored-blocks',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'deflate stored blocks of seven bytes' => [
            'deflate-stored-blocks-of-seven-bytes',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'deflate fixed codes' => [
            'deflate-fixed-codes',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'deflate five hundred empty stored blocks first' => [
            'deflate-five-hundred-empty-stored-blocks-first',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];
        yield 'deflate five thousand empty stored blocks first under the ceiling' => [
            'deflate-five-thousand-empty-stored-blocks-first-under-the-ceiling',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
            'an AuthnRequest',
            65_536,
        ];
        yield 'deflate high bit after the final block set' => [
            'deflate-high-bit-after-the-final-block-set',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
        ];

        // Section 3 row 10, B-9: RelayState.
        yield 'relay state carriage return and line feed' => [
            'relay-state-carriage-return-and-line-feed',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            "a\r\nb",
        ];
        yield 'relay state nul' => ['relay-state-nul', Authentication::Binding, self::AUTHN_REQUEST_ID, "sta\0te"];
        yield 'relay state a nul alone' => [
            'relay-state-a-nul-alone',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            "\0",
        ];
        yield 'relay state html' => [
            'relay-state-html',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            '<script>alert(1)</script>',
        ];
        yield 'relay state url of another site' => [
            'relay-state-url-of-another-site',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'https://attacker.example.com/',
        ];
        yield 'relay state invalid utf8' => [
            'relay-state-invalid-utf8',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            "\xFF\xFE",
        ];
        yield 'relay state utf8 unescaped' => [
            'relay-state-utf8-unescaped',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            "\u{e9}t\u{e9}",
        ];
        yield 'relay state space before' => [
            'relay-state-space-before',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            ' state',
        ];
        yield 'relay state space after' => [
            'relay-state-space-after',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state ',
        ];
        yield 'relay state a space alone' => [
            'relay-state-a-space-alone',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            ' ',
        ];
        yield 'relay state double percent encoded' => [
            'relay-state-double-percent-encoded',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            '%73tate',
        ];
        yield 'relay state 80 bytes written in 240 characters' => [
            'relay-state-80-bytes-written-in-240-characters',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            str_repeat('r', 80),
        ];
        yield 'relay state 80 spaces written plus' => [
            'relay-state-80-spaces-written-plus',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            str_repeat(' ', 80),
        ];
        yield 'relay state 80 bytes of characters of three bytes and two letters' => [
            'relay-state-80-bytes-of-characters-of-three-bytes-and-two-letters',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            str_repeat("\u{20ac}", 26) . 'ab',
        ];

        // Section 7, B-7, D-14: the bounds at and one over their value.
        yield 'bound query string of exactly the ceiling' => [
            'bound-query-string-of-exactly-the-ceiling',
            Authentication::Binding,
            self::AUTHN_REQUEST_ID,
            'state',
            'an AuthnRequest',
            65_536,
        ];
    }

    /**
     * Section 9.8, section 3 rows 1, 7, 8 and 10, B-1, B-7 to B-9, section 6.2: every form attempt that is refused, the
     * body a browser posts parsed by PHP's parser, given to PostReceiver::response(), then validated.
     *
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusedForms')]
    public function itRefusesAFormAttemptWithTheRuleNamed(
        string $attempt,
        string $exception,
        string $text,
        int $maxFormValueBytes = 1_572_864,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($text);

        // When
        $this->postAndValidate(self::fixture(AdversarialQueryBuilder::refused($attempt)), $maxFormValueBytes);
    }

    /**
     * @return iterable<string, array{0: string, 1: class-string<Throwable>, 2: string, 3?: int}>
     */
    public static function provideRefusedForms(): iterable
    {
        yield 'form index after saml response' => [
            'form-index-after-saml-response',
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'form two keys after saml response' => [
            'form-two-keys-after-saml-response',
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'form escaped brackets after saml response' => [
            'form-escaped-brackets-after-saml-response',
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'form brackets after saml request next to saml response' => [
            'form-brackets-after-saml-request-next-to-saml-response',
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'form lower case saml response alone' => [
            'form-lower-case-saml-response-alone',
            MalformedParameters::class,
            self::FORM_WITHOUT_MESSAGE,
        ];
        yield 'form dot after saml response' => [
            'form-dot-after-saml-response',
            MalformedParameters::class,
            self::FORM_WITHOUT_MESSAGE,
        ];
        yield 'form brackets after signature' => [
            'form-brackets-after-signature',
            Unsupported::class,
            self::SIGNATURE_IN_A_FORM,
        ];
        yield 'form empty sig alg' => ['form-empty-sig-alg', Unsupported::class, self::SIGNATURE_IN_A_FORM];
        yield 'form form feed in the message' => [
            'form-form-feed-in-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form vertical tab in the message' => [
            'form-vertical-tab-in-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form no break space in the message' => [
            'form-no-break-space-in-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form nul in the message' => ['form-nul-in-the-message', MalformedEncoding::class, self::NOT_BASE64];
        yield 'form padding in the middle of the message' => [
            'form-padding-in-the-middle-of-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form message percent encoded twice' => [
            'form-message-percent-encoded-twice',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form plus left unescaped in the message' => [
            'form-plus-left-unescaped-in-the-message',
            MalformedEncoding::class,
            self::NOT_BASE64,
        ];
        yield 'form relay state 81 bytes ending with a character of two bytes' => [
            'form-relay-state-81-bytes-ending-with-a-character-of-two-bytes',
            InvalidRelayState::class,
            self::RELAY_STATE_OVER_80_BYTES,
        ];
        yield 'form message one byte over max form value bytes' => [
            'form-message-one-byte-over-max-form-value-bytes',
            LimitExceeded::class,
            'The message field is longer than maxFormValueBytes, 3891 bytes (B-7).',
            self::RESPONSE_BASE64_BYTES - 1,
        ];
        yield 'form message under max form value bytes its line breaks over' => [
            'form-message-under-max-form-value-bytes-its-line-breaks-over',
            LimitExceeded::class,
            'The message field is longer than maxFormValueBytes, 3892 bytes (B-7).',
            self::RESPONSE_BASE64_BYTES,
        ];
    }

    /**
     * Section 9.8, section 3 rows 1, 8 and 10, B-1, B-8, B-9, section 6.2: every form attempt that is accepted, the
     * response read and validated, its RelayState returned as the parser decoded it.
     */
    #[Test]
    #[DataProvider('provideAcceptedForms')]
    public function itAcceptsAFormAttemptAsTheRulesSay(
        string $attempt,
        ?string $relayState,
        int $maxFormValueBytes = 1_572_864,
    ): void {
        // When
        $accepted = $this->postAndValidate(
            self::fixture(AdversarialQueryBuilder::accepted($attempt)),
            $maxFormValueBytes,
        );

        // Then
        static::assertSame(['_response', $relayState], $accepted);
    }

    /**
     * @return iterable<string, array{0: string, 1: ?string, 2?: int}>
     */
    public static function provideAcceptedForms(): iterable
    {
        yield 'form numeric names first' => ['form-numeric-names-first', null];
        yield 'form lower case saml response next to the message' => [
            'form-lower-case-saml-response-next-to-the-message',
            null,
        ];
        yield 'form space before saml response' => ['form-space-before-saml-response', null];
        yield 'form nul after saml response' => ['form-nul-after-saml-response', null];
        yield 'form saml encoding' => ['form-saml-encoding', null];
        yield 'form lower case sig alg' => ['form-lower-case-sig-alg', null];
        yield 'form saml response twice the last genuine' => ['form-saml-response-twice-the-last-genuine', null];
        yield 'form wrapped by carriage returns alone' => ['form-wrapped-by-carriage-returns-alone', null];
        yield 'form line feed every three characters' => ['form-line-feed-every-three-characters', null];
        yield 'form line breaks at both ends' => ['form-line-breaks-at-both-ends', null];
        yield 'form relay state carriage return and line feed' => [
            'form-relay-state-carriage-return-and-line-feed',
            "a\r\nb",
        ];
        yield 'form relay state nul' => ['form-relay-state-nul', "sta\0te"];
        yield 'form relay state html' => ['form-relay-state-html', '<script>alert(1)</script>'];
        yield 'form relay state 80 bytes of characters of three bytes and two letters' => [
            'form-relay-state-80-bytes-of-characters-of-three-bytes-and-two-letters',
            str_repeat("\u{20ac}", 26) . 'ab',
        ];
        yield 'form message of exactly max form value bytes' => [
            'form-message-of-exactly-max-form-value-bytes',
            null,
            self::RESPONSE_BASE64_BYTES,
        ];
    }

    /**
     * Section 9.8, section 9.4, B-2, B-3, B-8: the signed query strings and the response forms of SimpleSAMLphp and
     * Keycloak, one part changed, refused, each validated as RealDocumentsTest validates the capture it comes from.
     *
     * @param key-of<AdversarialQueryBuilder::REAL_CAPTURES> $capture
     * @param class-string<Throwable>                                                                     $exception
     */
    #[Test]
    #[DataProvider('provideRefusedRealCaptures')]
    public function itRefusesARealCaptureChangedWithTheRuleNamed(
        string $attempt,
        string $capture,
        string $exception,
        string $text,
    ): void {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($text);

        // When
        $this->receiveRealCapture($capture, self::fixture(AdversarialQueryBuilder::refused($attempt)));
    }

    /**
     * @return iterable<string, array{string, key-of<AdversarialQueryBuilder::REAL_CAPTURES>, class-string<Throwable>, string}>
     */
    public static function provideRefusedRealCaptures(): iterable
    {
        yield 'real simplesamlphp authn request message one character escaped' => [
            'real-simplesamlphp-authn-request-message-one-character-escaped',
            'simplesamlphp-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp authn request message one character changed' => [
            'real-simplesamlphp-authn-request-message-one-character-changed',
            'simplesamlphp-authn-request',
            MalformedEncoding::class,
            self::NOT_RAW_DEFLATE,
        ];
        yield 'real simplesamlphp authn request relay state one character escaped' => [
            'real-simplesamlphp-authn-request-relay-state-one-character-escaped',
            'simplesamlphp-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp authn request relay state one character changed' => [
            'real-simplesamlphp-authn-request-relay-state-one-character-changed',
            'simplesamlphp-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp authn request sig alg one character escaped' => [
            'real-simplesamlphp-authn-request-sig-alg-one-character-escaped',
            'simplesamlphp-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp authn request sig alg one character changed' => [
            'real-simplesamlphp-authn-request-sig-alg-one-character-changed',
            'simplesamlphp-authn-request',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'real simplesamlphp authn request signature one character changed' => [
            'real-simplesamlphp-authn-request-signature-one-character-changed',
            'simplesamlphp-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request message one character escaped' => [
            'real-keycloak-authn-request-message-one-character-escaped',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request message one character changed' => [
            'real-keycloak-authn-request-message-one-character-changed',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request relay state one character escaped' => [
            'real-keycloak-authn-request-relay-state-one-character-escaped',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request relay state one character changed' => [
            'real-keycloak-authn-request-relay-state-one-character-changed',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request sig alg one character escaped' => [
            'real-keycloak-authn-request-sig-alg-one-character-escaped',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak authn request sig alg one character changed' => [
            'real-keycloak-authn-request-sig-alg-one-character-changed',
            'keycloak-authn-request',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'real keycloak authn request signature one character changed' => [
            'real-keycloak-authn-request-signature-one-character-changed',
            'keycloak-authn-request',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp logout response message one character escaped' => [
            'real-simplesamlphp-logout-response-message-one-character-escaped',
            'simplesamlphp-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp logout response message one character changed' => [
            'real-simplesamlphp-logout-response-message-one-character-changed',
            'simplesamlphp-logout-response',
            MalformedXml::class,
            'libxml refused the input: error 41, level 3, at line 1, column 201 (I-3).',
        ];
        yield 'real simplesamlphp logout response relay state one character escaped' => [
            'real-simplesamlphp-logout-response-relay-state-one-character-escaped',
            'simplesamlphp-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp logout response relay state one character changed' => [
            'real-simplesamlphp-logout-response-relay-state-one-character-changed',
            'simplesamlphp-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp logout response sig alg one character escaped' => [
            'real-simplesamlphp-logout-response-sig-alg-one-character-escaped',
            'simplesamlphp-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp logout response sig alg one character changed' => [
            'real-simplesamlphp-logout-response-sig-alg-one-character-changed',
            'simplesamlphp-logout-response',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'real simplesamlphp logout response signature one character changed' => [
            'real-simplesamlphp-logout-response-signature-one-character-changed',
            'simplesamlphp-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak logout response message one character escaped' => [
            'real-keycloak-logout-response-message-one-character-escaped',
            'keycloak-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak logout response message one character changed' => [
            'real-keycloak-logout-response-message-one-character-changed',
            'keycloak-logout-response',
            InvalidId::class,
            'An ID is not an NCName (I-8).',
        ];
        yield 'real keycloak logout response relay state one character escaped' => [
            'real-keycloak-logout-response-relay-state-one-character-escaped',
            'keycloak-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak logout response relay state one character changed' => [
            'real-keycloak-logout-response-relay-state-one-character-changed',
            'keycloak-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak logout response sig alg one character escaped' => [
            'real-keycloak-logout-response-sig-alg-one-character-escaped',
            'keycloak-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real keycloak logout response sig alg one character changed' => [
            'real-keycloak-logout-response-sig-alg-one-character-changed',
            'keycloak-logout-response',
            UnknownSignatureAlgorithm::class,
            self::OFF_THE_LIST,
        ];
        yield 'real keycloak logout response signature one character changed' => [
            'real-keycloak-logout-response-signature-one-character-changed',
            'keycloak-logout-response',
            SignatureMismatch::class,
            self::NO_KEY_VERIFIES,
        ];
        yield 'real simplesamlphp response message one character changed' => [
            'real-simplesamlphp-response-message-one-character-changed',
            'simplesamlphp-response',
            DigestMismatch::class,
            'The claimed element is not what was signed (D-8).',
        ];
        yield 'real keycloak response message one character changed' => [
            'real-keycloak-response-message-one-character-changed',
            'keycloak-response',
            EncodingRefused::class,
            'The input is not valid UTF-8 (I-5).',
        ];
    }

    /**
     * Section 9.8, section 9.4, B-2, B-9: the real captures changed where nothing verifies the change, accepted: the
     * spelling of Signature, which the octets do not hold; the order of the parameters; SAMLEncoding, which nothing
     * signs; and the RelayState of a form, whose integrity over HTTP-POST is the consumer's (B-9, section 6.8).
     *
     * @param key-of<AdversarialQueryBuilder::REAL_CAPTURES> $capture
     */
    #[Test]
    #[DataProvider('provideAcceptedRealCaptures')]
    public function itAcceptsARealCaptureChangedAsTheRulesSay(
        string $attempt,
        string $capture,
        ?Authentication $authentication,
        string $id,
        string $relayState,
    ): void {
        // When
        $accepted = $this->receiveRealCapture($capture, self::fixture(AdversarialQueryBuilder::accepted($attempt)));

        // Then
        static::assertSame([$authentication, $id, $relayState], $accepted);
    }

    /**
     * @return iterable<string, array{string, key-of<AdversarialQueryBuilder::REAL_CAPTURES>, ?Authentication, string, string}>
     */
    public static function provideAcceptedRealCaptures(): iterable
    {
        yield 'real simplesamlphp authn request signature one character escaped' => [
            'real-simplesamlphp-authn-request-signature-one-character-escaped',
            'simplesamlphp-authn-request',
            Authentication::Binding,
            '_dcfb5cad9e75a4f54f05896bc454dbca210b085829',
            'http://localhost:8092/simplesaml/session.php',
        ];
        yield 'real simplesamlphp authn request parameters in reverse order' => [
            'real-simplesamlphp-authn-request-parameters-in-reverse-order',
            'simplesamlphp-authn-request',
            Authentication::Binding,
            '_dcfb5cad9e75a4f54f05896bc454dbca210b085829',
            'http://localhost:8092/simplesaml/session.php',
        ];
        yield 'real simplesamlphp authn request saml encoding added' => [
            'real-simplesamlphp-authn-request-saml-encoding-added',
            'simplesamlphp-authn-request',
            Authentication::Binding,
            '_dcfb5cad9e75a4f54f05896bc454dbca210b085829',
            'http://localhost:8092/simplesaml/session.php',
        ];
        yield 'real keycloak authn request signature one character escaped' => [
            'real-keycloak-authn-request-signature-one-character-escaped',
            'keycloak-authn-request',
            Authentication::Binding,
            'ID_3894a772-c6e9-416a-ad76-846f38c871e7',
            '-EyR6_MhiYlEDqynO29Wij-_WW7CjnpUloGSVEFjVnI.kyrCguQFzP4.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'real keycloak authn request parameters in reverse order' => [
            'real-keycloak-authn-request-parameters-in-reverse-order',
            'keycloak-authn-request',
            Authentication::Binding,
            'ID_3894a772-c6e9-416a-ad76-846f38c871e7',
            '-EyR6_MhiYlEDqynO29Wij-_WW7CjnpUloGSVEFjVnI.kyrCguQFzP4.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'real keycloak authn request saml encoding added' => [
            'real-keycloak-authn-request-saml-encoding-added',
            'keycloak-authn-request',
            Authentication::Binding,
            'ID_3894a772-c6e9-416a-ad76-846f38c871e7',
            '-EyR6_MhiYlEDqynO29Wij-_WW7CjnpUloGSVEFjVnI.kyrCguQFzP4.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'real simplesamlphp logout response signature one character escaped' => [
            'real-simplesamlphp-logout-response-signature-one-character-escaped',
            'simplesamlphp-logout-response',
            Authentication::Binding,
            '_10f52db37594bc20921006c87338d15333d7b87d26',
            'bindings logout ~',
        ];
        yield 'real simplesamlphp logout response parameters in reverse order' => [
            'real-simplesamlphp-logout-response-parameters-in-reverse-order',
            'simplesamlphp-logout-response',
            Authentication::Binding,
            '_10f52db37594bc20921006c87338d15333d7b87d26',
            'bindings logout ~',
        ];
        yield 'real simplesamlphp logout response saml encoding added' => [
            'real-simplesamlphp-logout-response-saml-encoding-added',
            'simplesamlphp-logout-response',
            Authentication::Binding,
            '_10f52db37594bc20921006c87338d15333d7b87d26',
            'bindings logout ~',
        ];
        yield 'real keycloak logout response signature one character escaped' => [
            'real-keycloak-logout-response-signature-one-character-escaped',
            'keycloak-logout-response',
            Authentication::Binding,
            'ID_cb3648a6-cb68-4f7e-9884-c136607e40e8',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
        yield 'real keycloak logout response parameters in reverse order' => [
            'real-keycloak-logout-response-parameters-in-reverse-order',
            'keycloak-logout-response',
            Authentication::Binding,
            'ID_cb3648a6-cb68-4f7e-9884-c136607e40e8',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
        yield 'real keycloak logout response saml encoding added' => [
            'real-keycloak-logout-response-saml-encoding-added',
            'keycloak-logout-response',
            Authentication::Binding,
            'ID_cb3648a6-cb68-4f7e-9884-c136607e40e8',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
        yield 'real simplesamlphp response relay state one character changed' => [
            'real-simplesamlphp-response-relay-state-one-character-changed',
            'simplesamlphp-response',
            null,
            '_f66f960182efa8c5bb823cfa34f88dc9ea47ec92dd',
            'cindings login ~',
        ];
        yield 'real keycloak response relay state one character changed' => [
            'real-keycloak-response-relay-state-one-character-changed',
            'keycloak-response',
            null,
            'ID_f3af97bf-4466-4106-8f81-0128f0440904',
            'cindings login ~',
        ];
    }

    /**
     * Section 9.8, B-1, section 6.2 step 1, section 6.8: fields no parser of a form gives, which a consumer could pass
     * all the same: a value of another type than a string, a list without names, a field of the detached signature
     * holding null. Each refused before anything is decoded.
     *
     * @param array<array-key, mixed>  $fields
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideFieldsNoParserGives')]
    public function itRefusesFieldsNoParserGivesWithTheRuleNamed(array $fields, string $exception, string $text): void
    {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($text);

        // When
        new PostReceiver(SamlLoader::create())->response($fields);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, class-string<Throwable>, string}>
     */
    public static function provideFieldsNoParserGives(): iterable
    {
        $message = base64_encode(self::fixture(self::RESPONSE));

        yield 'adversarial-form-relay-state-an-integer-refused' => [
            ['SAMLResponse' => $message, 'RelayState' => 80],
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'adversarial-form-saml-response-null-refused' => [
            ['SAMLResponse' => null],
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'adversarial-form-saml-response-true-refused' => [
            ['SAMLResponse' => true],
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'adversarial-form-saml-response-a-stringable-object-refused' => [
            ['SAMLResponse' => new readonly class($message) implements Stringable {
                public function __construct(
                    private string $message,
                ) {
                }

                public function __toString(): string
                {
                    return $this->message;
                }
            }],
            MalformedParameters::class,
            self::NOT_A_STRING,
        ];
        yield 'adversarial-form-a-list-of-the-values-refused' => [
            [$message, 'state'],
            MalformedParameters::class,
            self::FORM_WITHOUT_MESSAGE,
        ];
        yield 'adversarial-form-sig-alg-null-refused' => [
            ['SAMLResponse' => $message, 'SigAlg' => null],
            Unsupported::class,
            self::SIGNATURE_IN_A_FORM,
        ];
    }

    /**
     * Section 9.8, section 6.2 step 1: fields named by integers next to the message field, which a consumer's array
     * may hold, are skipped as any other field is.
     *
     * @param array<array-key, mixed> $fields
     */
    #[Test]
    #[DataProvider('provideFieldsNamedByIntegers')]
    public function itSkipsFieldsNamedByIntegers(array $fields): void
    {
        // When
        $accepted = new PostReceiver(SamlLoader::create())
            ->response($fields)
            ->validate(self::responseValidator(), self::identityProvider(), self::expectedResponse());

        // Then
        static::assertSame('_response', $accepted->responseId);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideFieldsNamedByIntegers(): iterable
    {
        yield 'adversarial-form-integer-names-next-to-the-message-accepted' => [
            [0 => 'x', 7 => 'y', 'SAMLResponse' => base64_encode(self::fixture(self::RESPONSE))],
        ];
    }

    /**
     * Section 9.8, B-5, section 5.2: a received message assembled by a closure bound to the scope of Reception, which
     * calls its private constructor with the message of one query string and the signature of another, is validated
     * through the binding's authentication: PHP lets code that leaves the scope it was given build what no path of the
     * package builds. The package cannot close it, as it cannot close a call of validateAuthenticatedByBinding() by the
     * consumer; both are the consumer's word, which section 6.8 bans in heidi/saml. Reflection reaches the same
     * (ReflectionProperty::setValue() on a Reception made without its constructor, a lazy ghost), measured outside the
     * suite, whose PHPStan rules ban the Reflection classes in tests/ as in src/ (section 8). Section 12 records the
     * question.
     *
     * @param Closure(Reception, Reception): Reception $assemble
     */
    #[Test]
    #[DataProvider('provideReceptionsAssembledOutsideTheirScope')]
    public function itValidatesAReceptionAssembledOutsideItsScopeAsTheConsumersWord(Closure $assemble): void
    {
        // Given
        $signed = self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))
                ->withRelayState('state')
                ->signed(),
            Service::SingleSignOn,
        );
        $forged = self::reception(
            RedirectQuery::carrying(
                'SAMLRequest',
                str_replace(
                    self::AUTHN_REQUEST_ID,
                    AdversarialQueryBuilder::FORGED_ID,
                    self::fixture(self::AUTHN_REQUEST),
                ),
            ),
            Service::SingleSignOn,
        );
        $assembled = $assemble->__invoke($signed, $forged);
        if (! $assembled instanceof Reception) {
            throw new LogicException('The closure assembles a Reception.');
        }

        // When
        $accepted = new ReceivedAuthnRequest($assembled)->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, AdversarialQueryBuilder::FORGED_ID],
            [$accepted->authentication, $accepted->request->id],
        );
    }

    /**
     * @return iterable<string, array{Closure(Reception, Reception): Reception}>
     */
    public static function provideReceptionsAssembledOutsideTheirScope(): iterable
    {
        yield 'adversarial-pairing-a-closure-bound-to-the-scope-of-reception-accepted' => [
            Closure::bind(
                static fn (Reception $signature, Reception $message): Reception => new Reception(
                    $message->message,
                    $signature->relayState,
                    $signature->binding,
                    $signature->signature,
                ),
                null,
                Reception::class,
            ) ?? throw new LogicException('PHP could not bind the closure.'),
        ];
    }

    /**
     * Section 9.8, B-5, section 5.2: a received message never travels as bytes: its serialization is refused by the
     * DOM it holds, and one unserialized from crafted bytes is refused by the type of its reception.
     *
     * @param Closure(): mixed        $attempt
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideSerializations')]
    public function itRefusesAReceivedMessageAsBytes(Closure $attempt, string $exception, string $text): void
    {
        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($text);

        // When
        $attempt->__invoke();
    }

    /**
     * @return iterable<string, array{Closure(): mixed, class-string<Throwable>, string}>
     */
    public static function provideSerializations(): iterable
    {
        $received = new ReceivedAuthnRequest(self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))
                ->withRelayState('state')
                ->signed(),
            Service::SingleSignOn,
        ));
        $property = "\0" . ReceivedAuthnRequest::class . "\0reception";

        yield 'adversarial-pairing-a-received-message-serialized-refused' => [
            static fn (): string => serialize($received),
            Exception::class,
            'Serialization of \'Dom\Element\' is not allowed, unless serialization methods are implemented in a subclass',
        ];
        yield 'adversarial-pairing-a-received-message-unserialized-from-crafted-bytes-refused' => [
            static fn (): mixed => unserialize(sprintf(
                'O:%d:"%s":1:{s:%d:"%s";N;}',
                strlen(ReceivedAuthnRequest::class),
                ReceivedAuthnRequest::class,
                strlen($property),
                $property,
            )),
            TypeError::class,
            'Cannot assign null to property Beffroi\Saml2\Bindings\ReceivedAuthnRequest::$reception of type Beffroi\Saml2\Bindings\Internal\Reception',
        ];
    }

    /**
     * Section 9.8, B-1, B-8, section 6.3 steps 1 and 6: a Destination whose own query holds names the receiver skips,
     * values it never decodes, and hosts it never reads, is sent, and the URL the sender writes is read by the package's
     * receiver and validated against that very URL: what the sender writes, the receiver reads.
     */
    #[Test]
    #[DataProvider('provideDestinationsSent')]
    public function itSendsADestinationAttemptTheReceiverReads(string $destination, string $separator): void
    {
        // Given
        $url = self::sender()->authnRequest(self::authnRequest($destination), self::signing('sp'), 'state');

        // When
        $accepted = self::receiver()
            ->authnRequest(self::queryString($url))
            ->validate(
                self::authnRequestValidator(),
                self::serviceProvider(),
                self::identityProviderAt($destination),
                $destination,
            );

        // Then
        static::assertSame(
            [true, Authentication::Binding],
            [str_starts_with($url, $destination . $separator . 'SAMLRequest='), $accepted->authentication],
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDestinationsSent(): iterable
    {
        yield 'adversarial-sender-destination-query-double-percent-encoded-name-accepted' => [
            self::SSO . '?SAML%2552equest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-nul-after-saml-request-accepted' => [
            self::SSO . '?SAMLRequest%00=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-space-before-saml-request-accepted' => [
            self::SSO . '?+SAMLRequest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-brackets-after-saml-request-accepted' => [
            self::SSO . '?SAMLRequest%5B%5D=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-lower-case-saml-request-accepted' => [
            self::SSO . '?samlrequest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-cyrillic-e-in-saml-request-accepted' => [
            self::SSO . '?SAMLR%D0%B5quest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-escaped-equals-in-a-name-accepted' => [
            self::SSO . '?SAMLRequest%3D=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-malformed-escape-in-a-value-accepted' => [
            self::SSO . '?tenant=%G1',
            '&',
        ];
        yield 'adversarial-sender-destination-query-question-mark-and-a-message-in-a-value-accepted' => [
            self::SSO . '?tenant=a?SAMLRequest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-semicolon-and-a-message-in-a-value-accepted' => [
            self::SSO . '?tenant=a;SAMLRequest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-query-ampersand-entity-before-saml-request-accepted' => [
            self::SSO . '?tenant=a&amp;SAMLRequest=x',
            '&',
        ];
        yield 'adversarial-sender-destination-empty-query-accepted' => [self::SSO . '?', '&'];
        yield 'adversarial-sender-destination-query-trailing-ampersand-accepted' => [self::SSO . '?tenant=acme&', '&'];
        yield 'adversarial-sender-destination-host-in-unicode-accepted' => [
            "https://idp.ex\u{e4}mple.com/saml/sso",
            '?',
        ];
        yield 'adversarial-sender-destination-host-in-punycode-accepted' => [
            'https://idp.xn--exmple-cua.com/saml/sso',
            '?',
        ];
        yield 'adversarial-sender-destination-host-percent-encoded-accepted' => [
            'https://idp.ex%61mple.com/saml/sso',
            '?',
        ];
        yield 'adversarial-sender-destination-user-information-accepted' => [
            'https://user:secret@idp.example.com/saml/sso',
            '?',
        ];
        yield 'adversarial-sender-destination-escaped-hash-in-the-path-accepted' => [
            'https://idp.example.com/saml/sso%23x',
            '?',
        ];
        yield 'adversarial-sender-destination-scheme-and-host-in-upper-case-and-a-default-port-accepted' => [
            'HTTPS://IDP.EXAMPLE.COM:443/saml/sso',
            '?',
        ];
    }

    /**
     * Section 9.8, B-1, section 6.3 step 1: a Destination whose own query names a parameter of the binding in a
     * spelling the corpus does not list, a lowercase percent-escape, is refused before the key is called.
     */
    #[Test]
    #[DataProvider('provideDestinationsRefused')]
    public function itRefusesADestinationAttemptBeforeTheKeyIsCalled(string $destination): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The query of the Destination holds a parameter of the binding (B-1).');

        // When
        self::sender()->authnRequest(self::authnRequest($destination), self::signing('sp'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDestinationsRefused(): iterable
    {
        yield 'adversarial-sender-destination-query-saml-response-in-lower-case-hexadecimal-refused' => [
            self::SSO . '?tenant=acme&SAMLRe%73ponse=x',
        ];
        yield 'adversarial-sender-destination-query-saml-request-twice-refused' => [
            self::SSO . '?SAMLRequest=a&SAMLRequest=b',
        ];
    }

    /**
     * Section 9.8, section 6.4 step 1: over HTTP-POST the Destination is the form's action as it is, its query holding
     * SAMLRequest included, since the receiver reads the body and never the action's query; the form is read and
     * validated.
     */
    #[Test]
    #[DataProvider('provideDestinationsPosted')]
    public function itPostsToADestinationAttemptAsItIs(string $destination): void
    {
        // Given
        $form = self::postSender()->authnRequest(self::authnRequest($destination), self::signing('sp'), 'state');

        // When
        $accepted = new PostReceiver(SamlLoader::create())
            ->authnRequest(BrowserForm::submitted($form))
            ->validate(
                self::authnRequestValidator(),
                self::serviceProvider(),
                self::identityProviderAt($destination),
                $destination,
            );

        // Then
        static::assertSame([$destination, Authentication::XmlSignature], [$form->action, $accepted->authentication]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDestinationsPosted(): iterable
    {
        yield 'adversarial-sender-post-destination-query-holding-saml-request-accepted' => [
            self::SSO . '?SAMLRequest=x',
        ];
    }

    /**
     * $queryString received by the method of $message under maxQueryStringBytes, then validated as the consumer does
     * with the parties of ReceptionFixtures: the authentication validation returned, the ID of the message validated,
     * and the RelayState returned.
     *
     * @param Message $message
     *
     * @return array{Authentication, string, ?string}
     */
    private function receiveAndValidate(string $message, string $queryString, int $maxQueryStringBytes): array
    {
        $receiver = new RedirectReceiver(SamlLoader::create(), new BindingLimits($maxQueryStringBytes));
        if ($message === 'an AuthnRequest') {
            $request = $receiver->authnRequest($queryString);
            $accepted = $request->validate(
                self::authnRequestValidator(),
                self::serviceProvider(),
                self::identityProvider(),
                self::SSO,
            );

            return [$accepted->authentication, $accepted->request->id, $request->relayState];
        }
        $received = $receiver->logoutMessage($queryString);
        if ($message === 'a LogoutRequest' && $received instanceof ReceivedLogoutRequest) {
            $accepted = $received->validate(
                self::logoutRequestValidator(),
                self::identityProvider(),
                self::serviceProvider(),
                self::SP_SLO,
            );

            return [$accepted->authentication, $accepted->request->id, $received->relayState];
        }
        if ($message === 'a LogoutResponse' && $received instanceof ReceivedLogoutResponse) {
            $accepted = $received->validate(
                self::logoutResponseValidator(),
                self::serviceProvider(),
                self::identityProvider(),
                self::IDP_SLO,
                self::LOGOUT_REQUEST_ID,
            );

            return [$accepted->authentication, $accepted->response->id, $received->relayState];
        }

        throw new LogicException(sprintf('The query string of the attempt is not received as %s.', $message));
    }

    /**
     * $body parsed by PHP's parser, given to PostReceiver::response() under maxFormValueBytes, then validated as the
     * service provider of ReceptionFixtures does: the ID of the response and the RelayState returned.
     *
     * @return array{string, ?string}
     */
    private function postAndValidate(string $body, int $maxFormValueBytes): array
    {
        $received = new PostReceiver(
            SamlLoader::create(),
            new BindingLimits(maxFormValueBytes: $maxFormValueBytes),
        )->response(BrowserForm::parsed($body));
        $accepted = $received->validate(self::responseValidator(), self::identityProvider(), self::expectedResponse());

        return [$accepted->responseId, $received->relayState];
    }

    /**
     * $bytes, a real capture changed, received and validated as RealDocumentsTest validates the capture it comes from,
     * with the parties, the clock and the URL of that test's case: the authentication validation returned, null for a
     * response, which carries none; the ID of the message validated; and the RelayState returned.
     *
     * @param key-of<AdversarialQueryBuilder::REAL_CAPTURES> $capture
     *
     * @return array{?Authentication, string, ?string}
     */
    private function receiveRealCapture(string $capture, string $bytes): array
    {
        $path = AdversarialQueryBuilder::REAL_CAPTURES[$capture];
        foreach (RealDocumentsTest::provideAuthnRequests() as $case) {
            if ($case[0] !== $path) {
                continue;
            }
            $received = self::receiver()->authnRequest($bytes);
            $accepted = $received->validate(
                new AuthnRequestValidator(SamlLoader::create(), $this->clockAt($case[1])),
                $this->realServiceProvider($case[2], $case[1]),
                $case[3],
                $case[4],
            );

            return [$accepted->authentication, $accepted->request->id, $received->relayState];
        }
        foreach (RealDocumentsTest::provideSignedLogoutResponseQueries() as $case) {
            if ($case[0] !== $path) {
                continue;
            }
            $received = self::receiver()->logoutMessage($bytes);
            if (! $received instanceof ReceivedLogoutResponse) {
                throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
            }
            $accepted = $received->validate(
                new LogoutResponseValidator(SamlLoader::create(), $this->clockAt($case[1])),
                $case[2],
                $case[3],
                $case[4],
                $case[5],
            );

            return [$accepted->authentication, $accepted->response->id, $received->relayState];
        }
        foreach (RealDocumentsTest::provideResponseForms() as $case) {
            if ($case[0] !== $path) {
                continue;
            }
            $received = self::postReceiver()->response(BrowserForm::parsed($bytes));
            $accepted = $received->validate(
                new ResponseValidator(SamlLoader::create(), $this->clockAt($case[1]), new InMemoryReplayGuard()),
                $case[2],
                ExpectedResponse::toRequest($case[3], $case[4], $case[5]),
            );

            return [null, $accepted->responseId, $received->relayState];
        }

        throw new LogicException(sprintf('RealDocumentsTest has no case for %s.', $path));
    }

    /**
     * A service provider of a real capture, its metadata as served, read by readTrusted() at the capture.
     */
    private function realServiceProvider(string $fixture, string $capturedAt): ServiceProvider
    {
        $descriptor = new MetadataReader(SamlLoader::create(), $this->clockAt($capturedAt))->readTrusted(
            SamlLoader::create()->load(self::fixture($fixture)),
        );

        return $descriptor->serviceProvider ?? throw new LogicException('The metadata holds a service provider.');
    }

    private function clockAt(string $now): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($now));
    }
}
