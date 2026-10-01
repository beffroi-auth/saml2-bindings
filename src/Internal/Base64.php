<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function base64_decode;
use function base64_encode;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use function str_replace;

/**
 * Base64 under B-8, the one class of the package that decodes it (section 8): the alphabet of RFC 4648 section 4 with
 * its padding and its unused bits zero, so that the decoded bytes encode back to the very text (RFC 4648 section 3.5).
 * The URL-safe alphabet of its section 5, a missing or an extra =, a set unused bit, a character outside the alphabet
 * and an empty text are refused. PHP's base64_decode(), strict as it is, skips whitespace and reads QQ and QR== as
 * QQ==: what it decoded is encoded again, and anything but the very text it was given is refused.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Base64
{
    /**
     * A value of a query string (HTTP-Redirect), with no whitespace at all (SAML Bindings §3.4.4.1), so that a + left
     * unescaped, a space once percent-decoded, is refused (section 6.1 steps 5 and 8).
     *
     * @throws MalformedEncoding when the text is empty or not the one form of RFC 4648 section 4
     */
    public static function decode(string $text): string
    {
        if ($text === '') {
            throw new MalformedEncoding('A base64 value is empty (B-8).');
        }
        $bytes = base64_decode($text, true);
        if ($bytes === false || base64_encode($bytes) !== $text) {
            throw new MalformedEncoding('A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).');
        }

        return $bytes;
    }

    /**
     * The value of a form (HTTP-POST), which may be wrapped in lines (RFC 2045 section 6.8): its carriage returns and
     * line feeds removed, wherever they are, then decoded as decode() does, so that any other whitespace is refused
     * (section 6.2 step 4).
     *
     * @throws MalformedEncoding when the text is empty once its line breaks are removed, or not the one form of RFC 4648
     *                           section 4
     */
    public static function decodeWrapped(string $text): string
    {
        return self::decode(str_replace(["\r", "\n"], '', $text));
    }

    /**
     * Bytes encoded in the alphabet of RFC 4648 section 4, padded, on one line (sections 6.3 step 3 and 6.4 step 3).
     */
    public static function encode(string $bytes): string
    {
        return base64_encode($bytes);
    }
}
