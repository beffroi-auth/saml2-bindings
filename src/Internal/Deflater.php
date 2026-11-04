<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function gzdeflate;
use LogicException;
use const ZLIB_ENCODING_RAW;

/**
 * RFC 1951, SAML Bindings §3.4.4.1 step 2
 *
 * @internal
 */
final readonly class Deflater
{
    public static function deflate(string $bytes): string
    {
        $deflated = gzdeflate($bytes, encoding: ZLIB_ENCODING_RAW);
        if ($deflated === false) {
            throw new LogicException('zlib could not deflate the message (section 6.3).');
        }

        return $deflated;
    }
}
