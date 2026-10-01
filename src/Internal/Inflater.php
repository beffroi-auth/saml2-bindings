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
 * The bounded inflater of B-7 and B-8, the one class of the package that inflates (section 8): raw DEFLATE (RFC 1951,
 * SAML Bindings §3.4.4.1 step 2), neither the zlib wrapper of RFC 1950 nor the gzip one of RFC 1952, the stream ending
 * with its final block and nothing after it.
 *
 * The input is inflated one byte at a time and the length of the output checked after each byte, so that the output is
 * refused at the first byte that takes it over the bound, never measured once it is whole (section 6.1 step 8): what
 * is held past the bound is the output of one byte, at most 1 032 bytes (a length of 258 coded in two bits). One byte is
 * the step because no smaller one exists and any larger one is a tuning no test can tell from its neighbour. Once the
 * final block is read, nothing more is fed to zlib, which would start a second stream on it.
 *
 * zlib reports a stream it cannot read with a PHP warning: an error handler of its own, set around each step and
 * restored in a finally, keeps every warning from the caller, whose handler is in place again when the step returns.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Inflater
{
    /**
     * @param int $maxBytes the bound of the output, maxInflatedBytes of section 7
     *
     * @throws LimitExceeded when the output exceeds $maxBytes
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
     * One byte of input, inflated, what zlib reports as it reads it kept from the caller.
     *
     * @throws MalformedEncoding when zlib cannot read the stream
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
