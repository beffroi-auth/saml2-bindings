<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * The clock port of model.md section 5.2, frozen at an instant in UTC: now() returns it however often it is read. The
 * package reads no time; the model's validators the tests drive do, and read this one (section 9.7). A test moves time
 * by taking another clock from movedBy(), never by sleeping; this one never changes. Copied from saml2-model's
 * tests/Support/ at commit 9c833c5.
 */
final readonly class FrozenClock implements ClockInterface
{
    private DateTimeImmutable $now;

    public function __construct(DateTimeImmutable $now)
    {
        $this->now = $now->setTimezone(new DateTimeZone('UTC'));
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    /**
     * A new clock, $seconds later, or earlier when negative.
     */
    public function movedBy(int $seconds): self
    {
        return new self($this->now->modify(sprintf('%+d seconds', $seconds)));
    }
}
