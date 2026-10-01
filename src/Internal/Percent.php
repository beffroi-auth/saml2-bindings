<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use function preg_match;
use function rawurlencode;
use function urldecode;

/**
 * The percent codec of B-8, the one class of the package that decodes or encodes a percent-escape (section 8).
 *
 * Decoding reads the application/x-www-form-urlencoded form of the URL Standard, which a browser writes and PHP's own
 * parser of a query string applies: a % followed by two hexadecimal digits, of either case, is the byte they name, and
 * a + is a space; any other % is refused, never kept as it is. Encoding writes RFC 3986: every byte outside the
 * unreserved characters of its section 2.3, ALPHA, DIGIT, -, ., _ and ~, as % and two uppercase hexadecimal digits
 * (section 2.1), as SimpleSAMLphp writes its query strings (section 6.3 step 3).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Percent
{
    /**
     * A name or a value of a query string, decoded (B-8).
     *
     * @throws MalformedEncoding when a % is not followed by two hexadecimal digits
     */
    public static function decode(string $encoded): string
    {
        // preg_match() returns 0, 1 or false: anything but 0, a failure of PCRE included, refuses.
        if (preg_match('~%(?![0-9A-Fa-f]{2})~', $encoded) !== 0) {
            throw new MalformedEncoding('A percent-escape is not a % followed by two hexadecimal digits (B-8).');
        }

        return urldecode($encoded);
    }

    /**
     * Bytes encoded for a query string: the unreserved characters of RFC 3986 as they are, every other byte escaped in
     * uppercase hexadecimal (section 6.3 step 3).
     */
    public static function encode(string $bytes): string
    {
        return rawurlencode($bytes);
    }
}
