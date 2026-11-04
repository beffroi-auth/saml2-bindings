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
 * Section 6.1 steps 2 to 7, B-1, B-2, B-3, B-7, B-8, B-9
 *
 * @internal
 */
final readonly class QueryParameters
{
    public const string DEFLATE = 'urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE';

    private const array PARAMETERS = [
        'SAMLRequest',
        'SAMLResponse',
        'RelayState',
        'SigAlg',
        'Signature',
        'SAMLEncoding',
    ];

    /**
     * B-9: a named exception to the 80 bytes of SAML Bindings §3.4.3 and §3.5.3.
     */
    private const int MAX_RELAY_STATE_BYTES = 1_024;

    /**
     * The base64 of Dsig's maxSignatureValueBytes, 1 024 bytes.
     */
    private const int MAX_SIGNATURE_CHARACTERS = 1_368;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     * @param string                       $message          still percent-encoded
     * @param ?string                      $relayState       decoded
     */
    private function __construct(
        public string $messageParameter,
        public string $message,
        public ?string $relayState,
        public ?DetachedSignature $signature,
    ) {
    }

    /**
     * @param string                                       $queryString       the raw query string, already bounded
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters
     *
     * @throws MalformedParameters
     * @throws MalformedEncoding
     * @throws Unsupported
     * @throws UnknownSignatureAlgorithm
     * @throws LimitExceeded
     * @throws InvalidRelayState
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
     * Section 6.1 step 2
     *
     * Reads a name as php_register_variable_ex() does, so that a consumer reading the query string through PHP's parser
     * never sees a parameter the package did not read (B-1).
     *
     * @throws MalformedEncoding
     */
    public static function parameterNamed(string $name): ?string
    {
        $read = ltrim(Percent::decode($name), ' ');
        $read = substr($read, 0, strcspn($read, "\0["));

        return in_array($read, self::PARAMETERS, true) ? $read : null;
    }

    /**
     * Section 6.1 step 2
     *
     * @return array<string, string> the raw value of each parameter, by name
     *
     * @throws MalformedEncoding
     * @throws MalformedParameters
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
     * Section 6.1 step 3
     *
     * @param array<string, string>                        $parameters
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     *
     * @return array{'SAMLRequest'|'SAMLResponse', string} the message parameter and its raw value
     *
     * @throws MalformedParameters
     * @throws MalformedEncoding when the value is empty
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
     * Section 6.1 steps 5 and 7
     *
     * @param array<string, string>        $parameters
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     *
     * @throws MalformedParameters
     * @throws UnknownSignatureAlgorithm
     * @throws MalformedEncoding
     * @throws LimitExceeded
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
     * Section 6.1 step 5
     *
     * @throws LimitExceeded
     * @throws MalformedEncoding
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
     * Section 6.1 step 6
     *
     * @throws MalformedEncoding
     * @throws InvalidRelayState
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
