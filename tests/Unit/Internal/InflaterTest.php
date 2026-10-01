<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Inflater;
use Beffroi\Saml2\Bindings\Tests\Support\DeflateBomb;
use function deflate_add;
use function deflate_init;
use function gzcompress;
use function gzencode;
use function intdiv;
use LogicException;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function restore_error_handler;
use function set_error_handler;
use function strlen;
use function substr;
use const ZLIB_ENCODING_RAW;
use const ZLIB_FINISH;
use const ZLIB_FIXED;
use const ZLIB_FULL_FLUSH;
use const ZLIB_SYNC_FLUSH;

/**
 * B-7, B-8, section 6.1 step 8: raw DEFLATE (RFC 1951, SAML Bindings §3.4.4.1 step 2), inflated one byte at a time
 * under a bound, the stream complete and nothing after it, no warning of zlib reaching the caller.
 */
final class InflaterTest extends TestCase
{
    use CodecFixtures;

    private const string MESSAGE = 'behaviour/authn-request-unsigned.xml';

    /**
     * B-8, RFC 1951: a raw DEFLATE stream is the message it encodes, whatever the blocks and the codes the deflater
     * chose.
     */
    #[Test]
    #[DataProvider('provideRawStreams')]
    public function itInflatesARawDeflateStream(string $deflated): void
    {
        // When
        $inflated = Inflater::inflate($deflated, 65_536);

        // Then
        static::assertSame(self::fixture(self::MESSAGE), $inflated);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRawStreams(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'the default level, as SimpleSAMLphp writes it' => [self::deflated($message)];
        yield 'level 9' => [self::deflated($message, ['level' => 9])];
        yield 'level 0, stored blocks' => [self::deflated($message, ['level' => 0])];
        yield 'fixed Huffman codes' => [self::deflated($message, ['strategy' => ZLIB_FIXED])];
        yield 'two blocks' => [self::inTwoBlocks($message)];
    }

    /**
     * B-8, RFC 1951 §3.2.3: an empty final block is a complete stream, of nothing.
     */
    #[Test]
    public function itInflatesAnEmptyStream(): void
    {
        // When
        $inflated = Inflater::inflate(self::deflated(''), 65_536);

        // Then
        static::assertSame('', $inflated);
    }

    /**
     * B-7, section 7: a message of exactly the bound is accepted.
     */
    #[Test]
    public function itAcceptsAMessageOfExactlyTheBound(): void
    {
        // Given
        $message = self::fixture(self::MESSAGE);

        // When
        $inflated = Inflater::inflate(self::deflated($message), strlen($message));

        // Then
        static::assertSame($message, $inflated);
    }

    /**
     * §9.2 row 22, B-7, B-11: a message one byte over the bound is refused, the bound named and nothing of the message
     * carried.
     */
    #[Test]
    public function itRefusesAMessageOneByteOverTheBound(): void
    {
        // Given
        $message = self::fixture(self::MESSAGE);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 507 bytes (B-7).');

        // When
        Inflater::inflate(self::deflated($message), strlen($message) - 1);
    }

    /**
     * §9.2 row 22, B-7: a stream of about 1 MiB that inflates to 1 GiB is refused at the default bound of 64 KiB.
     */
    #[Test]
    public function itRefusesADeflateBomb(): void
    {
        // Given
        $bomb = DeflateBomb::inflatingTo(1024);

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 65536 bytes (B-7).');

        // When
        Inflater::inflate($bomb, 65_536);
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8: the output is refused while inflation runs, never measured once whole: a
     * bomb whose final block is replaced by a block of the reserved type is refused at the bound, before inflation
     * reaches what it could not read.
     */
    #[Test]
    public function itRefusesTheOutputWhileInflationRuns(): void
    {
        // Given
        $bomb = substr(DeflateBomb::inflatingTo(1024), 0, -2) . "\x07";

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 65536 bytes (B-7).');

        // When
        Inflater::inflate($bomb, 65_536);
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8: the memory a bomb of 1 GiB costs before its refusal is the bound, plus the
     * output of one byte of input, at most 1 032 bytes, plus zlib's fixed state: its inflate state, 8 416 bytes with
     * its object, its window of 32 KiB, and the buffer of about 12 KiB inflate_add() takes for a step. The classes are
     * loaded before the measure, which is the inflation alone. Measured on 1 October 2026, zlib 1.3.1, the same on PHP
     * 8.5.10 and 8.4.25, Xdebug collecting coverage or not: the peak over the bound is 53 744 bytes at 1 KiB, 55 656 at
     * 64 KiB and 57 968 at 1 MiB, where the bomb inflated whole would hold 1 073 741 824. The ceiling asserted is the
     * bound, one byte's output and 64 KiB for zlib.
     */
    #[Test]
    #[DataProvider('provideBounds')]
    public function itHoldsABombWithinTheBoundPlusOneStep(int $bound): void
    {
        // Given
        $bomb = DeflateBomb::inflatingTo(1024);
        $this->inflateAndForget($bomb, 1);
        $before = memory_get_usage();
        memory_reset_peak_usage();

        // When
        $this->inflateAndForget($bomb, $bound);

        // Then
        static::assertLessThan($bound + 1_032 + 65_536, memory_get_peak_usage() - $before);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideBounds(): iterable
    {
        yield '1 KiB' => [1_024];
        yield 'the default, 64 KiB' => [65_536];
        yield 'the ceiling, 1 MiB' => [1_048_576];
    }

    /**
     * §9.2 row 24, B-8, B-11, RFC 1950, RFC 1952: what is not raw DEFLATE, a zlib or a gzip wrapper among it, is
     * refused, and the refusal carries nothing of it.
     */
    #[Test]
    #[DataProvider('provideStreamsThatAreNotRawDeflate')]
    public function itRefusesWhatIsNotRawDeflate(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The message is not raw DEFLATE (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsThatAreNotRawDeflate(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'wrapped by zlib, RFC 1950' => [self::wrapped(gzcompress($message))];
        yield 'wrapped by gzip, RFC 1952' => [self::wrapped(gzencode($message))];
        yield 'the message itself, not deflated' => [$message];
        yield 'a block of the reserved type' => ["\x07"];
    }

    /**
     * §9.2 row 24, B-8, RFC 1951 §3.2.3: a stream cut before its final block is refused.
     */
    #[Test]
    #[DataProvider('provideCutStreams')]
    public function itRefusesAStreamCutBeforeItsFinalBlock(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The DEFLATE stream ends before its final block (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCutStreams(): iterable
    {
        $message = self::fixture(self::MESSAGE);
        $deflated = self::deflated($message);

        yield 'its last byte cut' => [substr($deflated, 0, -1)];
        yield 'cut in the middle' => [substr($deflated, 0, intdiv(strlen($deflated), 2))];
        yield 'a block that is not final, flushed' => [self::deflated($message, [], ZLIB_SYNC_FLUSH)];
        yield 'nothing' => [''];
    }

    /**
     * §9.2 row 24, B-8, RFC 1951 §3.2.3: a byte after the final block is refused, whatever it is.
     */
    #[Test]
    #[DataProvider('provideStreamsFollowedByBytes')]
    public function itRefusesBytesAfterTheFinalBlock(string $deflated): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('Bytes follow the final block of the DEFLATE stream (B-8).');

        // When
        Inflater::inflate($deflated, 65_536);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsFollowedByBytes(): iterable
    {
        $deflated = self::deflated(self::fixture(self::MESSAGE));

        yield 'a NUL' => [$deflated . "\0"];
        yield 'an empty final block' => [$deflated . self::deflated('')];
        yield 'the stream a second time' => [$deflated . $deflated];
    }

    /**
     * B-8: zlib reports a stream it cannot read with a PHP warning, which never reaches the caller's error handler.
     */
    #[Test]
    public function itLetsNoWarningOfZlibReachTheCaller(): void
    {
        // Given
        $reported = [];
        set_error_handler(static function (int $level, string $message) use (&$reported): bool {
            $reported[] = $message;

            return true;
        });

        // When
        try {
            Inflater::inflate(self::wrapped(gzencode(self::fixture(self::MESSAGE))), 65_536);
        } catch (MalformedEncoding) {
        } finally {
            restore_error_handler();
        }

        // Then
        static::assertSame([], $reported);
    }

    /**
     * B-8: the error handler the inflater sets around each step is gone when it returns, whether it accepts or refuses,
     * and the caller's is in place again.
     */
    #[Test]
    #[DataProvider('provideStreamsAcceptedAndRefused')]
    public function itGivesTheCallerItsErrorHandlerBack(string $deflated): void
    {
        // Given
        $handler = static fn (): bool => true;
        set_error_handler($handler);

        // When
        try {
            Inflater::inflate($deflated, 65_536);
        } catch (MalformedEncoding) {
        }
        $current = set_error_handler(null);
        restore_error_handler();
        restore_error_handler();

        // Then
        static::assertSame($handler, $current);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideStreamsAcceptedAndRefused(): iterable
    {
        $message = self::fixture(self::MESSAGE);

        yield 'accepted' => [self::deflated($message)];
        yield 'refused by zlib' => [self::wrapped(gzencode($message))];
    }

    /**
     * $deflated inflated under $bound, its refusal for exceeding the bound swallowed: what is measured is the state it
     * leaves.
     */
    private function inflateAndForget(string $deflated, int $bound): void
    {
        try {
            Inflater::inflate($deflated, $bound);
        } catch (LimitExceeded) {
        }
    }

    /**
     * $bytes deflated by zlib, raw (RFC 1951), its last block flushed as $flush says.
     *
     * @param array<string, int> $options
     */
    private static function deflated(string $bytes, array $options = [], int $flush = ZLIB_FINISH): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW, $options);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }

        return self::wrapped(deflate_add($context, $bytes, $flush));
    }

    /**
     * $bytes deflated by zlib in one stream of two blocks, the first ended by a full flush.
     */
    private static function inTwoBlocks(string $bytes): string
    {
        $context = deflate_init(ZLIB_ENCODING_RAW);
        if ($context === false) {
            throw new LogicException('zlib could not start a deflation.');
        }

        return (
            self::wrapped(deflate_add($context, substr($bytes, 0, 200), ZLIB_FULL_FLUSH))
            . self::wrapped(deflate_add($context, substr($bytes, 200), ZLIB_FINISH))
        );
    }

    /**
     * What a function of zlib returned, a failure of zlib stopping the test.
     */
    private static function wrapped(string|false $bytes): string
    {
        if ($bytes === false) {
            throw new LogicException('zlib failed on a fixture.');
        }

        return $bytes;
    }
}
