<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use InflateContext;
use function inflate_add;
use function inflate_get_read_len;
use function inflate_get_status;
use function inflate_init;
use LogicException;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function strlen;
use const ZLIB_ENCODING_RAW;
use const ZLIB_STREAM_END;
use const ZLIB_SYNC_FLUSH;

/**
 * B-7, B-8. The input is inflated one byte at a time, so that the output is refused at the first byte over the bound,
 * never once whole; after the final block nothing is fed to zlib, which would start a second stream on it.
 *
 * @internal
 */
final readonly class Inflater
{
    /**
     * @throws LimitExceeded
     * @throws MalformedEncoding when the input is not raw DEFLATE, ends before its final block or has bytes after it
     */
    public static function inflate(string $deflated, int $maxBytes): string
    {
        $context = inflate_init(ZLIB_ENCODING_RAW);
        if ($context === false) {
            throw new LogicException('zlib could not start an inflation (section 6.1).');
        }
        $length = strlen($deflated);
        $inflated = '';
        for ($offset = 0; $offset < $length; ++$offset) {
            $inflated .= self::step($context, $deflated[$offset]);
            if (strlen($inflated) > $maxBytes) {
                throw new LimitExceeded(sprintf(
                    'The inflated message is longer than maxInflatedBytes, %d bytes (B-7).',
                    $maxBytes,
                ));
            }
            if (inflate_get_status($context) === ZLIB_STREAM_END) {
                break;
            }
        }
        if (inflate_get_status($context) !== ZLIB_STREAM_END) {
            throw new MalformedEncoding('The DEFLATE stream ends before its final block (B-8).');
        }
        if (inflate_get_read_len($context) !== $length) {
            throw new MalformedEncoding('Bytes follow the final block of the DEFLATE stream (B-8).');
        }

        return $inflated;
    }

    /**
     * zlib reports a stream it cannot read with a PHP warning, kept from the caller by an error handler of its own.
     *
     * @throws MalformedEncoding
     */
    private static function step(InflateContext $context, string $byte): string
    {
        set_error_handler(static fn (): bool => true);
        try {
            $inflated = inflate_add($context, $byte, ZLIB_SYNC_FLUSH);
            if ($inflated === false) {
                throw new MalformedEncoding('The message is not raw DEFLATE (B-8).');
            }

            return $inflated;
        } finally {
            restore_error_handler();
        }
    }
}
