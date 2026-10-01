<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\PostForm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, section 6.7: the form PostSender writes holds its action and its fields as they are given, in their
 * order, nothing escaped for HTML, which is the page's. SAML Bindings §3.5.4.
 */
final class PostFormTest extends TestCase
{
    /**
     * Section 6.7, SAML Bindings §3.5.4: the action and the fields, in their order, as given, an ampersand and markup
     * left unescaped.
     */
    #[Test]
    public function itHoldsItsActionAndFieldsAsGiven(): void
    {
        // When
        $form = new PostForm(
            'https://sp.example.com/saml/acs?tenant=acme&lang=fr',
            ['SAMLResponse' => 'PHg+', 'RelayState' => '<b>"&\'</b>'],
        );

        // Then
        static::assertSame(
            [
                'https://sp.example.com/saml/acs?tenant=acme&lang=fr',
                ['SAMLResponse' => 'PHg+', 'RelayState' => '<b>"&\'</b>'],
            ],
            [$form->action, $form->fields],
        );
    }
}
