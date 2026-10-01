<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function gzdeflate;
use LogicException;
use const ZLIB_ENCODING_RAW;

/**
 * The deflater of HTTP-Redirect, the one class of the package that deflates (section 8): raw DEFLATE (RFC 1951, SAML
 * Bindings §3.4.4.1 step 2), without the zlib wrapper of RFC 1950 or the gzip one of RFC 1952, at zlib's default level,
 * as SimpleSAMLphp deflates its messages (section 6.3 step 3).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Deflater
{
    /**
     * The serialized message, deflated (section 6.3 step 3).
     */
    public static function deflate(string $bytes): string
    {
        $deflated = gzdeflate($bytes, encoding: ZLIB_ENCODING_RAW);
        if ($deflated === false) {
            throw new LogicException('zlib could not deflate the message (section 6.3).');
        }

        return $deflated;
    }
}
