<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use function preg_match;
use function rawurlencode;
use function urldecode;

/**
 * B-8, RFC 3986 §2.1
 *
 * Decodes a + as a space, as browsers and PHP's query string parser do; encodes as SimpleSAMLphp does.
 *
 * @internal
 */
final readonly class Percent
{
    /**
     * @throws MalformedEncoding
     */
    public static function decode(string $encoded): string
    {
        // Anything but 0 refuses, a failure of PCRE (false) included.
        if (preg_match('~%(?![0-9A-Fa-f]{2})~', $encoded) !== 0) {
            throw new MalformedEncoding('A percent-escape is not a % followed by two hexadecimal digits (B-8).');
        }

        return urldecode($encoded);
    }

    public static function encode(string $bytes): string
    {
        return rawurlencode($bytes);
    }
}
