<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Support;

use Beffroi\Saml2\Bindings\PostForm;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The browser and the parser of the tests' forms (sections 6.7, 6.8, 9.1), checked against PHP alone: the body is the
 * application/x-www-form-urlencoded encoding of the URL Standard, and its fields are what PHP's parser gives back, so
 * that a row of the corpus posts what a browser posts and receives what a consumer receives.
 */
final class BrowserFormTest extends TestCase
{
    /**
     * URL Standard §5: each name and value encoded, a space as "+", "+", "/" and "=" of base64 percent-encoded, in the
     * order given.
     */
    #[Test]
    public function itEncodesTheBodyAsABrowserDoes(): void
    {
        // When
        $body = BrowserForm::body([
            ['SAMLResponse',   'ab+/=='],
            ['RelayState',     'a b&c'],
            ['SAMLResponse[]', 'x'],
        ]);

        // Then
        static::assertSame('SAMLResponse=ab%2B%2F%3D%3D&RelayState=a+b%26c&SAMLResponse%5B%5D=x', $body);
    }

    /**
     * Section 6.8: PHP's parser gives the fields back as they were posted, line breaks among them, and makes an array
     * of a field named with brackets.
     */
    #[Test]
    public function itGivesTheFieldsAsPhpParsesThem(): void
    {
        // When
        $fields = BrowserForm::posted([
            ['SAMLResponse', "ab+/\r\n=="],
            ['RelayState',   'a b&c'],
            ['RelayState[]', 'x'],
        ]);

        // Then
        static::assertSame(['SAMLResponse' => "ab+/\r\n==", 'RelayState' => ['x']], $fields);
    }

    /**
     * Section 6.7: the fields of a PostForm, posted by a browser and parsed by PHP, are the fields of the form, the
     * action aside.
     */
    #[Test]
    public function itSubmitsTheFieldsOfAPostForm(): void
    {
        // Given
        $form = new PostForm('https://sp.example.com/saml/acs?a=b', [
            'SAMLResponse' => 'ab+/==',
            'RelayState' => '<a b>',
        ]);

        // When
        $fields = BrowserForm::submitted($form);

        // Then
        static::assertSame(['SAMLResponse' => 'ab+/==', 'RelayState' => '<a b>'], $fields);
    }
}
