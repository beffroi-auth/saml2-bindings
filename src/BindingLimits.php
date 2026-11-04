<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use InvalidArgumentException;
use function sprintf;

/**
 * Each bound may be raised up to its ceiling, never removed (B-7). A length the specification fixes, of a RelayState
 * or of a Signature, is a rule of the value and not a bound.
 */
final readonly class BindingLimits
{
    private const int MAX_QUERY_STRING_BYTES_CEILING = 65_536;

    /**
     * Core's default maxBytes (core.md section 7)
     */
    private const int MAX_INFLATED_BYTES_CEILING = 1_048_576;

    /**
     * The base64 of Core's ceiling of maxBytes, 8 MiB, wrapped at 76 characters, fits under it.
     */
    private const int MAX_FORM_VALUE_BYTES_CEILING = 12_582_912;

    /**
     * @throws InvalidArgumentException when a value is under 1 or over its ceiling
     */
    public function __construct(
        public int $maxQueryStringBytes = 8_192,
        public int $maxInflatedBytes = 65_536,
        public int $maxFormValueBytes = 1_572_864,
    ) {
        $this->check('maxQueryStringBytes', $maxQueryStringBytes, self::MAX_QUERY_STRING_BYTES_CEILING);
        $this->check('maxInflatedBytes', $maxInflatedBytes, self::MAX_INFLATED_BYTES_CEILING);
        $this->check('maxFormValueBytes', $maxFormValueBytes, self::MAX_FORM_VALUE_BYTES_CEILING);
    }

    private function check(string $bound, int $value, int $ceiling): void
    {
        if ($value < 1 || $value > $ceiling) {
            throw new InvalidArgumentException(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));
        }
    }
}
