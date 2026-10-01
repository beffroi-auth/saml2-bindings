<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function array_map;
use Beffroi\Saml2\Bindings\Internal\Deflater;
use Beffroi\Saml2\Bindings\Internal\Inflater;
use function chr;
use function gzinflate;
use function implode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function strlen;

/**
 * B-8, section 6.3 step 3: what the package sends over HTTP-Redirect is raw DEFLATE (RFC 1951, SAML Bindings §3.4.4.1
 * step 2), which its own inflater reads back.
 */
final class DeflaterTest extends TestCase
{
    use CodecFixtures;

    /**
     * §9.3 row 11, B-8, RFC 1951, SAML Bindings §3.4.4.1 step 2: the deflated message is raw DEFLATE, which zlib's own
     * reader of raw DEFLATE, a reader of neither wrapper, gives back as it was.
     */
    #[Test]
    #[DataProvider('provideMessages')]
    public function itDeflatesToRawDeflate(string $message): void
    {
        // When
        $deflated = Deflater::deflate($message);

        // Then
        static::assertSame($message, gzinflate($deflated));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMessages(): iterable
    {
        yield 'an AuthnRequest' => [self::fixture('behaviour/authn-request-unsigned.xml')];
        yield 'nothing' => [''];
        yield 'every byte' => [implode('', array_map(chr(...), range(0, 255)))];
    }

    /**
     * B-7, B-8, section 6.1 step 8: what the package deflates, its inflater reads back under a bound of the message's
     * own length.
     */
    #[Test]
    #[DataProvider('provideMessages')]
    public function itDeflatesWhatTheInflaterReads(string $message): void
    {
        // When
        $deflated = Deflater::deflate($message);

        // Then
        static::assertSame($message, Inflater::inflate($deflated, strlen($message)));
    }
}
