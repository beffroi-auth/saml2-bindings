<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Support;

use Beffroi\Saml2\Bindings\Tests\Support\DeflateBomb;
use function inflate_add;
use function inflate_get_read_len;
use function inflate_get_status;
use function inflate_init;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_split;
use function strlen;
use const ZLIB_ENCODING_RAW;
use const ZLIB_STREAM_END;
use const ZLIB_SYNC_FLUSH;

/**
 * §9.2 row 22, B-7: the bomb the tests of the inflater are given is what it says, measured without the inflater under
 * test, by zlib itself, in chunks, none of them kept.
 */
final class DeflateBombTest extends TestCase
{
    /**
     * §9.2 row 22, RFC 1951: about 1 MiB that inflates to 1 GiB, as one complete raw DEFLATE stream.
     */
    #[Test]
    public function itInflatesAMebibyteToAGibibyte(): void
    {
        // Given
        $bomb = DeflateBomb::inflatingTo(1024);
        $context = inflate_init(ZLIB_ENCODING_RAW);
        static::assertNotFalse($context);
        $inflated = 0;

        // When
        foreach (str_split($bomb, 4096) as $chunk) {
            $output = inflate_add($context, $chunk, ZLIB_SYNC_FLUSH);
            static::assertIsString($output);
            $inflated += strlen($output);
        }

        // Then
        static::assertLessThan(1_100_000, strlen($bomb));
        static::assertSame(
            [1_073_741_824, ZLIB_STREAM_END, strlen($bomb)],
            [$inflated, inflate_get_status($context), inflate_get_read_len($context)],
        );
    }
}
