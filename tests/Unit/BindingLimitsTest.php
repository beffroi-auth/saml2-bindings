<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\BindingLimits;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * B-7, section 5.1 and section 7: three bounds, each with a default and a ceiling, never a switch that removes a check.
 */
final class BindingLimitsTest extends TestCase
{
    /**
     * Section 7: the defaults.
     */
    #[Test]
    public function itHoldsTheDefaultsOfSection7(): void
    {
        // When
        $limits = new BindingLimits();

        // Then
        static::assertSame(
            [8_192, 65_536, 1_572_864],
            [$limits->maxQueryStringBytes, $limits->maxInflatedBytes, $limits->maxFormValueBytes],
        );
    }

    /**
     * Section 7: a bound may be raised up to its ceiling.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itAcceptsABoundAtItsCeiling(string $bound, int $ceiling): void
    {
        // When
        $limits = new BindingLimits(...[$bound => $ceiling]);

        // Then
        static::assertSame($ceiling, $this->read($limits, $bound));
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function provideCeilings(): iterable
    {
        yield 'maxQueryStringBytes' => ['maxQueryStringBytes', 65_536];
        yield 'maxInflatedBytes' => ['maxInflatedBytes', 1_048_576];
        yield 'maxFormValueBytes' => ['maxFormValueBytes', 12_582_912];
    }

    /**
     * Section 5.4: a value over the ceiling is a programming error of the caller.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itRefusesABoundOverItsCeiling(string $bound, int $ceiling): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));

        // When
        new BindingLimits(...[$bound => $ceiling + 1]);
    }

    /**
     * Section 7: a bound may be lowered down to one byte.
     */
    #[Test]
    #[DataProvider('provideBounds')]
    public function itAcceptsABoundOfOne(string $bound): void
    {
        // When
        $limits = new BindingLimits(...[$bound => 1]);

        // Then
        static::assertSame(1, $this->read($limits, $bound));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBounds(): iterable
    {
        yield 'maxQueryStringBytes' => ['maxQueryStringBytes'];
        yield 'maxInflatedBytes' => ['maxInflatedBytes'];
        yield 'maxFormValueBytes' => ['maxFormValueBytes'];
    }

    /**
     * Section 5.4, B-7: a value under 1 is a programming error, and never a switch that removes the check.
     */
    #[Test]
    #[DataProvider('provideCeilings')]
    public function itRefusesABoundUnderOne(string $bound, int $ceiling): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs(sprintf('%s must be between 1 and %d (section 7).', $bound, $ceiling));

        // When
        new BindingLimits(...[$bound => 0]);
    }

    private function read(BindingLimits $limits, string $bound): int
    {
        return match ($bound) {
            'maxQueryStringBytes' => $limits->maxQueryStringBytes,
            'maxInflatedBytes' => $limits->maxInflatedBytes,
            'maxFormValueBytes' => $limits->maxFormValueBytes,
            default => throw new InvalidArgumentException(sprintf('%s is not a bound.', $bound)),
        };
    }
}
