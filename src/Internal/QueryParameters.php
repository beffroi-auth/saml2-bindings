<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function array_key_exists;
use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function explode;
use function in_array;
use function ltrim;
use function sprintf;
use function strcspn;
use function strlen;
use function substr;

/**
 * The parameters of a query string received over HTTP-Redirect, read in the order of section 6.1, steps 2 to 7, before
 * anything decodes the message: the six parameters the binding reads, each at most once and under its literal name
 * (B-1), exactly one message parameter, the one the method takes (B-1), SAMLEncoding absent or DEFLATE (section 8),
 * SigAlg and Signature both or neither, SigAlg on the closed list of D-5 (B-3), the text of Signature bounded then
 * decoded (B-7, B-8), RelayState decoded and bounded (B-9), and the octets the signature covers (B-2).
 *
 * Every value is kept as the substring of the query string exactly as it arrived; the message is the one raw value the
 * signed octets hold, never another occurrence (B-1, B-2). A name is read as PHP's own parser of a query string reads
 * it, percent-decoded, its leading spaces dropped, cut at its first NUL or "[": one that reads so as one of the six
 * while it is not written so is refused, so that a consumer reading the query string through that parser too never
 * sees a parameter the package did not read (B-1). Any other parameter, the query of a Location among them, is skipped
 * once its name is decoded, its value decoded no further and never signed (SAML Bindings §3.4.4.1).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class QueryParameters
{
    /**
     * The one value of SAMLEncoding the package reads (SAML Bindings §3.4.4.1).
     */
    public const string DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE';

    /**
     * The six parameters of B-1, the only ones the binding reads.
     */
    private const array PARAMETERS = [
        'SAMLRequest',
        'SAMLResponse',
        'RelayState',
        'SigAlg',
        'Signature',
        'SAMLEncoding',
    ];

    /**
     * SAML Bindings §3.4.3 (B-9).
     */
    private const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * The base64 of 1 024 bytes, Dsig's maxSignatureValueBytes (section 7).
     */
    private const int MAX_SIGNATURE_CHARACTERS = 1_368;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message parameter the query string carries
     * @param string                       $message          its value, as it arrived, still percent-encoded
     * @param ?string                      $relayState       RelayState, decoded, or null when the query string has none
     * @param ?DetachedSignature           $signature        the detached signature, or null when the query string is
     *                                                       unsigned
     */
    private function __construct(
        public string $messageParameter,
        public string $message,
        public ?string $relayState,
        public ?DetachedSignature $signature,
    ) {
    }

    /**
     * Section 6.1 steps 2 to 7, in their order.
     *
     * @param string                                       $queryString       the raw query string, already bounded
     *                                                                        (section 6.1 step 1)
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters the message parameters the method takes
     * @param Loader                                       $loader            the consumer's, which the detached
     *                                                                        signature is verified with (step 12)
     *
     * @throws MalformedParameters       when the parameters are not those B-1 and B-3 allow
     * @throws MalformedEncoding         when a name or a value is not in its one form (B-8), or the message is empty
     * @throws Unsupported               when SAMLEncoding is not DEFLATE (section 8)
     * @throws UnknownSignatureAlgorithm when SigAlg is not on the closed list (D-5, B-3)
     * @throws LimitExceeded             when the text of Signature is longer than 1 368 characters (section 7)
     * @throws InvalidRelayState         when RelayState is empty or longer than 80 bytes (B-9)
     */
    public static function read(string $queryString, array $messageParameters, Loader $loader): self
    {
        $parameters = self::parameters($queryString);
        [$messageParameter, $message] = self::message($parameters, $messageParameters);
        $encoding = $parameters['SAMLEncoding'] ?? null;
        if ($encoding !== null && Percent::decode($encoding) !== self::DEFLATE) {
            throw new Unsupported('A SAMLEncoding other than DEFLATE is refused (section 8).');
        }
        $signature = self::signature($parameters, $messageParameter, $message, $loader);

        return new self($messageParameter, $message, self::relayState($parameters['RelayState'] ?? null), $signature);
    }

    /**
     * Section 6.1 step 2: the parameter of B-1 a name of a query string reads as, as PHP's own parser of a query string
     * reads it (php_register_variable_ex()): percent-decoded under B-8, its leading spaces dropped, cut at its first
     * NUL or "[". Null when it reads as none of the six. The sender reads the query of a Destination with it, as the
     * receiver will (section 6.3 step 1).
     *
     * @param string $name a name as it arrived, still percent-encoded
     *
     * @return ?string one of the six parameters of B-1, or null
     *
     * @throws MalformedEncoding when the name holds a malformed percent-escape (B-8)
     */
    public static function parameterNamed(string $name): ?string
    {
        $read = ltrim(Percent::decode($name), ' ');
        $read = substr($read, 0, strcspn($read, "\0["));

        return in_array($read, self::PARAMETERS, true) ? $read : null;
    }

    /**
     * Step 2: the raw value of each of the six parameters of B-1 the query string carries. Split on & alone, a ; being
     * a character of a value; each segment split on its first =; its name read as parameterNamed() reads it. An empty
     * segment has an empty name, which is none of the six, and is skipped as any other parameter is.
     *
     * @return array<string, string>
     *
     * @throws MalformedEncoding   when a name holds a malformed percent-escape (B-8)
     * @throws MalformedParameters when one of the six is named otherwise than as written, has no =, or appears twice
     *                             (B-1)
     */
    private static function parameters(string $queryString): array
    {
        $parameters = [];
        foreach (explode('&', $queryString) as $segment) {
            $pair = explode('=', $segment, 2);
            $name = self::parameterNamed($pair[0]);
            if ($name === null) {
                continue;
            }
            if ($name !== $pair[0]) {
                throw new MalformedParameters('A name reads as a parameter of the binding once percent-decoded, its leading spaces dropped or cut at a NUL or a "[" (B-1).');
            }
            $value = $pair[1] ?? null;
            if ($value === null) {
                throw new MalformedParameters('A parameter of the binding has no "=" (B-1).');
            }
            if (array_key_exists($name, $parameters)) {
                throw new MalformedParameters('A parameter of the binding appears more than once (B-1).');
            }
            $parameters[$name] = $value;
        }

        return $parameters;
    }

    /**
     * Step 3: exactly one of SAMLRequest and SAMLResponse, one the method takes, not empty.
     *
     * @param array<string, string>                        $parameters
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     *
     * @return array{'SAMLRequest'|'SAMLResponse', string} the message parameter and its raw value
     *
     * @throws MalformedParameters when the query string carries both, neither, or one the method does not take (B-1)
     * @throws MalformedEncoding   when its value is empty
     */
    private static function message(array $parameters, array $accepted): array
    {
        $request = $parameters['SAMLRequest'] ?? null;
        $response = $parameters['SAMLResponse'] ?? null;
        if ($request !== null && $response !== null) {
            throw new MalformedParameters('The query string carries both SAMLRequest and SAMLResponse (B-1).');
        }
        [$name, $value] = match (true) {
            $request !== null => ['SAMLRequest', $request],
            $response !== null => ['SAMLResponse', $response],
            default => throw new MalformedParameters('The query string carries neither SAMLRequest nor SAMLResponse (B-1).'),
        };
        if (! in_array($name, $accepted, true)) {
            throw new MalformedParameters('The query string carries a message parameter the method does not take (B-1).');
        }
        if ($value === '') {
            throw new MalformedEncoding('The message parameter is empty (B-8).');
        }

        return [$name, $value];
    }

    /**
     * Steps 5 and 7: SigAlg and Signature both or neither; SigAlg, percent-decoded, on the closed list of D-5, before
     * the message is decoded; the text of Signature, percent-decoded, bounded, then decoded as base64 without
     * whitespace; and the octets of B-2 from the raw values.
     *
     * @param array<string, string>        $parameters
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     *
     * @throws MalformedParameters       when one of SigAlg and Signature is present without the other (B-3)
     * @throws UnknownSignatureAlgorithm when SigAlg is not on the closed list (D-5)
     * @throws MalformedEncoding         when a value is not in its one form (B-8)
     * @throws LimitExceeded             when the text of Signature is longer than 1 368 characters (section 7)
     */
    private static function signature(
        array $parameters,
        string $messageParameter,
        string $message,
        Loader $loader,
    ): ?DetachedSignature {
        $sigAlg = $parameters['SigAlg'] ?? null;
        $signature = $parameters['Signature'] ?? null;

        return match (true) {
            $sigAlg === null && $signature === null => null,
            $sigAlg !== null && $signature !== null => new DetachedSignature(
                SignatureAlgorithm::fromUri(Percent::decode($sigAlg)),
                self::signatureValue($signature),
                new SignedOctets($messageParameter, $message, $parameters['RelayState'] ?? null, $sigAlg),
                $loader,
            ),
            default => throw new MalformedParameters('SigAlg and Signature are both present or both absent (B-3).'),
        };
    }

    /**
     * Step 5: the text of Signature, percent-decoded, at most the base64 of 1 024 bytes, then decoded under B-8.
     *
     * @throws LimitExceeded     when the text is longer than 1 368 characters (section 7)
     * @throws MalformedEncoding when it is empty or not base64 in its one form without whitespace (B-8)
     */
    private static function signatureValue(string $raw): string
    {
        $text = Percent::decode($raw);
        if (strlen($text) > self::MAX_SIGNATURE_CHARACTERS) {
            throw new LimitExceeded(sprintf(
                'The text of Signature is longer than %d characters (section 7).',
                self::MAX_SIGNATURE_CHARACTERS,
            ));
        }

        return Base64::decode($text);
    }

    /**
     * Step 6: RelayState, when present, percent-decoded, neither empty nor longer than 80 bytes, kept as decoded.
     *
     * @throws MalformedEncoding when it holds a malformed percent-escape (B-8)
     * @throws InvalidRelayState when it is empty or longer than 80 bytes (B-9)
     */
    private static function relayState(?string $raw): ?string
    {
        if ($raw === null) {
            return null;
        }
        $relayState = Percent::decode($raw);
        if ($relayState === '') {
            throw new InvalidRelayState('The RelayState is empty (B-9).');
        }
        if (strlen($relayState) > self::MAX_RELAY_STATE_BYTES) {
            throw new InvalidRelayState(sprintf(
                'The RelayState is longer than %d bytes (B-9).',
                self::MAX_RELAY_STATE_BYTES,
            ));
        }

        return $relayState;
    }
}
