<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function base64_decode;
use function base64_encode;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use function str_replace;

/**
 * B-8. PHP's base64_decode(), even strict, skips whitespace and reads QR== as QQ==: what it decoded is encoded again
 * and must be the very text it was given.
 *
 * @internal
 */
final readonly class Base64
{
    /**
     * No whitespace at all (SAML Bindings §3.4.4.1), so that a + left unescaped, a space once percent-decoded, is
     * refused.
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
     * @throws MalformedEncoding when the text is empty once its line breaks are removed, or not the one form of
     *                           RFC 4648 section 4
     */
    public static function decodeWrapped(string $text): string
    {
        return self::decode(str_replace(["\r", "\n"], '', $text));
    }

    public static function encode(string $bytes): string
    {
        return base64_encode($bytes);
    }
}
