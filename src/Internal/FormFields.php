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
 * Section 6.2 steps 1 to 3. The consumer's parser decoded the form: nothing here percent-decodes.
 *
 * @internal
 */
final readonly class FormFields
{
    private const array FIELDS = ['SAMLRequest', 'SAMLResponse', 'RelayState'];

    /**
     * SAML Bindings §3.5.4
     */
    private const array SIGNATURE_FIELDS = ['SigAlg', 'Signature'];

    /**
     * B-9: 1 024 bytes once decoded, a named and bounded exception to the 80 bytes of SAML Bindings §3.4.3 and §3.5.3
     * (section 8).
     */
    private const int MAX_RELAY_STATE_BYTES = 1_024;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     * @param string                       $message          still base64
     */
    private function __construct(
        public string $messageParameter,
        public string $message,
        public ?string $relayState,
    ) {
    }

    /**
     * Section 6.2 steps 1 to 3, in their order
     *
     * @param array<array-key, mixed>                      $fields
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters
     *
     * @throws MalformedParameters
     * @throws Unsupported       when SigAlg or Signature is present
     * @throws LimitExceeded
     * @throws MalformedEncoding when the message field is empty
     * @throws InvalidRelayState when RelayState is empty or longer than 1 024 bytes
     */
    public static function read(array $fields, array $messageParameters, int $maxFormValueBytes): self
    {
        $read = self::fields($fields);
        [$messageParameter, $message] = self::message($read, $messageParameters, $maxFormValueBytes);

        return new self($messageParameter, $message, self::relayState($read['RelayState'] ?? null));
    }

    /**
     * Section 6.2 step 1
     *
     * @param array<array-key, mixed> $fields
     *
     * @return array<string, string>
     *
     * @throws MalformedParameters when a field the binding reads is not a string
     * @throws Unsupported         when SigAlg or Signature is present
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
     * Section 6.2 step 2
     *
     * @param array<string, string>                        $fields
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     *
     * @return array{'SAMLRequest'|'SAMLResponse', string}
     *
     * @throws MalformedParameters when the form carries both, neither, or one the method does not take
     * @throws LimitExceeded
     * @throws MalformedEncoding   when its value is empty
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
     * Section 6.2 step 3
     *
     * @throws InvalidRelayState when it is empty or longer than 1 024 bytes
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
