<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function deflate_add;
use function deflate_init;
use LogicException;
use function str_repeat;
use const ZLIB_ENCODING_RAW;
use const ZLIB_FINISH;
use const ZLIB_SYNC_FLUSH;

/**
 * A DEFLATE bomb (§9.2 row 22): a raw DEFLATE stream (RFC 1951) of zeros, about a thousandth of what it inflates to,
 * built without ever holding what it inflates to. zlib deflates one mebibyte of zeros, flushed to a byte boundary, then
 * a second one, which, its window full of zeros already, every later mebibyte would deflate to the same bytes: the
 * stream is the first, the second repeated, and an empty final block. 1 GiB is 1 060 867 bytes of it.
 */
final readonly class DeflateBomb
{
    private const int MEBIBYTE = 1_048_576;

    /**
     * @param positive-int $mebibytes what the stream inflates to, in mebibytes of zeros
     */
    public static function inflatingTo(int $mebibytes): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW, ['level' => 9]);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }
        $zeros = str_repeat("\0", self::MEBIBYTE);
        $first = deflate_add($context, $zeros, ZLIB_SYNC_FLUSH);
        $next = deflate_add($context, $zeros, ZLIB_SYNC_FLUSH);
        $final = deflate_add($context, '', ZLIB_FINISH);
        if ($first === false || $next === false || $final === false) {
            throw new LogicException('zlib could not deflate the bomb.');
        }

        return $first . str_repeat($next, $mebibytes - 1) . $final;
    }
}
