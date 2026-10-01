<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Exception;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4, B-4: a signed query string from a peer without a signing key, refused with the rest of what the
 * package refuses.
 */
final class NoVerificationKeyTest extends TestCase
{
    #[Test]
    public function itIsABindingRefused(): void
    {
        // When / Then
        static::assertContains(BindingRefused::class, class_parents(NoVerificationKey::class));
    }
}
