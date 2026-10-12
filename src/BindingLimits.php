<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use InvalidArgumentException;
use function sprintf;

/**
 * The three bounds of section 7 the package chooses (section 5.1): each a quantity in bytes a caller may raise up to its
 * ceiling for a documented reason, never a switch that removes a check (B-7). The lengths the specification fixes, a
 * RelayState of 1 024 bytes and the text of a Signature, are rules of the value, not bounds, and are not here.
 */
final readonly class BindingLimits
{
    private const int MAX_QUERY_STRING_BYTES_CEILING = 65_536;

    /**
     * Section 7: Core's default maxBytes (core.md section 7).
     */
    private const int MAX_INFLATED_BYTES_CEILING = 1_048_576;

    /**
     * Section 7: the base64 of Core's ceiling of maxBytes, 8 MiB, wrapped at 76 characters, fits under it.
     */
    private const int MAX_FORM_VALUE_BYTES_CEILING = 12_582_912;

    /**
     * @param int $maxQueryStringBytes the raw query string of HTTP-Redirect, received or sent, before anything reads it
     * @param int $maxInflatedBytes    the message HTTP-Redirect carries, once inflated, refused while inflation runs
     * @param int $maxFormValueBytes   the message field of an HTTP-POST form, before it is decoded
     *
     * @throws InvalidArgumentException when a value is under 1 or over its ceiling of section 7, a programming error of
     *                                  the caller
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
