<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Exception;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Exception\XmlSignatureRefused;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4, B-6: an XML signature over HTTP-Redirect, refused with the rest of what the package refuses.
 */
final class XmlSignatureRefusedTest extends TestCase
{
    #[Test]
    public function itIsABindingRefused(): void
    {
        // When / Then
        static::assertContains(BindingRefused::class, class_parents(XmlSignatureRefused::class));
    }
}
