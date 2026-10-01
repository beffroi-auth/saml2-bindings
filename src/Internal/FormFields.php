<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function array_key_exists;
use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use function in_array;
use function is_string;
use function sprintf;
use function strlen;

/**
 * The fields of a form received over HTTP-POST, read in the order of section 6.2, steps 1 to 3, before anything
 * decodes the message: the three fields the binding reads, each a string, never an array (B-1), no detached signature
 * (section 8), exactly one message field, the one the method takes (B-1), bounded before it is decoded (B-7), and
 * RelayState neither empty nor longer than 80 bytes (B-9). The consumer's parser decoded the form (section 6.8):
 * nothing here percent-decodes, and the values are kept as they were given. Any other field, a submit button for
 * instance, is skipped.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class FormFields
{
    /**
     * The three fields of B-1 a form carries, the only ones the binding reads.
     */
    private const array FIELDS = ['SAMLRequest', 'SAMLResponse', 'RelayState'];

    /**
     * The fields of HTTP-Redirect's detached signature, which a form never carries (SAML Bindings §3.5.4).
     */
    private const array SIGNATURE_FIELDS = ['SigAlg', 'Signature'];

    /**
     * SAML Bindings §3.5.3 (B-9).
     */
    private const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message field the form carries
     * @param string                       $message          its value, as the consumer's parser decoded it, still
     *                                                       base64
     * @param ?string                      $relayState       RelayState, as given, or null when the form has none
     */
    private function __construct(
        public string $messageParameter,
        public string $message,
        public ?string $relayState,
    ) {
    }

    /**
     * Section 6.2 steps 1 to 3, in their order.
     *
     * @param array<array-key, mixed>                      $fields            the fields of the form, as the consumer's
     *                                                                        parser decoded them (section 6.8)
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters the message fields the method takes
     * @param int                                          $maxFormValueBytes the bound of the message field (section 7)
     *
     * @throws MalformedParameters when the fields are not those B-1 allows
     * @throws Unsupported         when SigAlg or Signature is present (section 8)
     * @throws LimitExceeded       when the message field is longer than maxFormValueBytes (B-7)
     * @throws MalformedEncoding   when the message field is empty (B-8)
     * @throws InvalidRelayState   when RelayState is empty or longer than 80 bytes (B-9)
     */
    public static function read(array $fields, array $messageParameters, int $maxFormValueBytes): self
    {
        $read = self::fields($fields);
        [$messageParameter, $message] = self::message($read, $messageParameters, $maxFormValueBytes);

        return new self($messageParameter, $message, self::relayState($read['RelayState'] ?? null));
    }

    /**
     * Step 1: the three fields of B-1 the form carries, each a string; SigAlg and Signature absent; any other field
     * skipped.
     *
     * @param array<array-key, mixed> $fields
     *
     * @return array<string, string>
     *
     * @throws MalformedParameters when one of the three is not a string, an array for instance (B-1)
     * @throws Unsupported         when SigAlg or Signature is present (section 8)
     */
    private static function fields(array $fields): array
    {
        $read = [];
        foreach (self::FIELDS as $name) {
            if (! array_key_exists($name, $fields)) {
                continue;
            }
            $value = $fields[$name];
            if (! is_string($value)) {
                throw new MalformedParameters('A field of the binding is not a string, an array for instance (B-1).');
            }
            $read[$name] = $value;
        }
        foreach (self::SIGNATURE_FIELDS as $name) {
            if (array_key_exists($name, $fields)) {
                throw new Unsupported('SigAlg or Signature in a form is refused: HTTP-POST carries no detached signature (section 8).');
            }
        }

        return $read;
    }

    /**
     * Step 2: exactly one of SAMLRequest and SAMLResponse, one the method takes, bounded, not empty.
     *
     * @param array<string, string>                        $fields
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     *
     * @return array{'SAMLRequest'|'SAMLResponse', string} the message field and its value
     *
     * @throws MalformedParameters when the form carries both, neither, or one the method does not take (B-1)
     * @throws LimitExceeded       when its value is longer than maxFormValueBytes (B-7)
     * @throws MalformedEncoding   when its value is empty (B-8)
     */
    private static function message(array $fields, array $accepted, int $maxFormValueBytes): array
    {
        $request = $fields['SAMLRequest'] ?? null;
        $response = $fields['SAMLResponse'] ?? null;
        if ($request !== null && $response !== null) {
            throw new MalformedParameters('The form carries both SAMLRequest and SAMLResponse (B-1).');
        }
        [$name, $value] = match (true) {
            $request !== null => ['SAMLRequest', $request],
            $response !== null => ['SAMLResponse', $response],
            default => throw new MalformedParameters('The form carries neither SAMLRequest nor SAMLResponse (B-1).'),
        };
        if (! in_array($name, $accepted, true)) {
            throw new MalformedParameters('The form carries a message field the method does not take (B-1).');
        }
        if (strlen($value) > $maxFormValueBytes) {
            throw new LimitExceeded(sprintf(
                'The message field is longer than maxFormValueBytes, %d bytes (B-7).',
                $maxFormValueBytes,
            ));
        }
        if ($value === '') {
            throw new MalformedEncoding('The message field is empty (B-8).');
        }

        return [$name, $value];
    }

    /**
     * Step 3: RelayState, when present, neither empty nor longer than 80 bytes, kept as given: the consumer's parser
     * decoded it.
     *
     * @throws InvalidRelayState when it is empty or longer than 80 bytes (B-9)
     */
    private static function relayState(?string $relayState): ?string
    {
        if ($relayState === null) {
            return null;
        }
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
