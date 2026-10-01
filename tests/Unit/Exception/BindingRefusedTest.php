<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Exception;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Xml\Core\Exception\RefusedXml;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.4: a BindingRefused is a RefusedXml of Core, so that a consumer catching that base class catches everything
 * the stack refuses, the package's refusals with those of Core, Dsig and the model.
 */
final class BindingRefusedTest extends TestCase
{
    #[Test]
    public function itIsARefusedXml(): void
    {
        // When / Then
        static::assertContains(RefusedXml::class, class_parents(BindingRefused::class));
    }
}
