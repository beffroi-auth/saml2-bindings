<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Saml2\Bindings\Internal\FormFields;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * Section 6.2 steps 1 to 3, B-1, B-7, B-8, B-9: the fields of a form, as the consumer's parser decoded them, read before
 * anything decodes the message: the three fields the binding reads, strings, exactly one message field, the one the
 * method takes, bounded and not empty, RelayState bounded and kept as given, no SigAlg and no Signature, any other
 * field skipped. SAML Bindings §3.5.4.
 */
final class FormFieldsTest extends TestCase
{
    /**
     * The bound of the message field the tests give, unless a test names another.
     */
    private const int BOUND = 1_572_864;

    /**
     * Section 6.2 steps 2 and 3, B-9, SAML Bindings §3.5.3: the message field and its value, and RelayState kept as
     * given, never percent-decoded: the consumer's parser decoded the form.
     */
    #[Test]
    public function itReadsTheMessageFieldAndRelayStateAsGiven(): void
    {
        // When
        $fields = FormFields::read(
            ['SAMLResponse' => 'PHg+', 'RelayState' => 'a%20b+c'],
            ['SAMLResponse'],
            self::BOUND,
        );

        // Then
        static::assertSame(
            ['SAMLResponse', 'PHg+', 'a%20b+c'],
            [$fields->messageParameter, $fields->message, $fields->relayState],
        );
    }

    /**
     * Section 6.2 step 2, B-1: a SAMLRequest is read where the method takes it, at a single sign-on service and at a
     * single logout service, without RelayState.
     *
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     */
    #[Test]
    #[DataProvider('provideMethodsTakingASamlRequest')]
    public function itReadsASamlRequest(array $accepted): void
    {
        // When
        $fields = FormFields::read(['SAMLRequest' => 'PHg+'], $accepted, self::BOUND);

        // Then
        static::assertSame(
            ['SAMLRequest', 'PHg+', null],
            [$fields->messageParameter, $fields->message, $fields->relayState],
        );
    }

    /**
     * @return iterable<string, array{non-empty-list<'SAMLRequest'|'SAMLResponse'>}>
     */
    public static function provideMethodsTakingASamlRequest(): iterable
    {
        yield 'authnRequest()' => [['SAMLRequest']];
        yield 'logoutMessage()' => [['SAMLRequest', 'SAMLResponse']];
    }

    /**
     * §9.3 row 10, section 6.2 step 1, SAML Bindings §3.5.4: a field other than the three, a submit button, a field of
     * an integer name or holding an array, is skipped.
     *
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideOtherFields')]
    public function itSkipsTheOtherFields(array $form): void
    {
        // When
        $fields = FormFields::read($form, ['SAMLRequest', 'SAMLResponse'], self::BOUND);

        // Then
        static::assertSame(
            ['SAMLResponse', 'PHg+', 'state'],
            [$fields->messageParameter, $fields->message, $fields->relayState],
        );
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideOtherFields(): iterable
    {
        yield 'a submit button, last' => [['SAMLResponse' => 'PHg+', 'RelayState' => 'state', 'submit' => 'Submit']];
        yield 'a submit button, first' => [['submit' => 'Submit', 'SAMLResponse' => 'PHg+', 'RelayState' => 'state']];
        yield 'a field of an integer name' => [[0 => 'x', 'SAMLResponse' => 'PHg+', 'RelayState' => 'state']];
        yield 'another field holding an array' => [['SAMLResponse' => 'PHg+', 'RelayState' => 'state', 'a' => ['b']]];
        yield 'a name of another case' => [['SAMLResponse' => 'PHg+', 'RelayState' => 'state', 'samlrequest' => 'x']];
    }

    /**
     * §9.2 row 2, B-1, section 6.2 step 2, CVE-2025-27773: SAMLRequest and SAMLResponse in one form are refused, whatever
     * the method, before anything is decoded.
     *
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     */
    #[Test]
    #[DataProvider('provideEveryMethod')]
    public function itRefusesBothMessageFields(array $accepted): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries both SAMLRequest and SAMLResponse (B-1).');

        // When
        FormFields::read(['SAMLRequest' => 'PHg+', 'SAMLResponse' => 'PHk+'], $accepted, self::BOUND);
    }

    /**
     * @return iterable<string, array{non-empty-list<'SAMLRequest'|'SAMLResponse'>}>
     */
    public static function provideEveryMethod(): iterable
    {
        yield 'response()' => [['SAMLResponse']];
        yield 'authnRequest()' => [['SAMLRequest']];
        yield 'logoutMessage()' => [['SAMLRequest', 'SAMLResponse']];
    }

    /**
     * §9.2 row 3, B-1, section 6.2 step 2: a form without SAMLRequest nor SAMLResponse is refused.
     *
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideFormsWithoutMessage')]
    public function itRefusesAFormWithoutMessageField(array $form): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries neither SAMLRequest nor SAMLResponse (B-1).');

        // When
        FormFields::read($form, ['SAMLRequest', 'SAMLResponse'], self::BOUND);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideFormsWithoutMessage(): iterable
    {
        yield 'no field' => [[]];
        yield 'RelayState alone' => [['RelayState' => 'state']];
        yield 'another field alone' => [['submit' => 'Submit']];
    }

    /**
     * §9.2 row 4, B-1, section 6.2 step 2: a SAMLResponse given to authnRequest(), a SAMLRequest given to response(),
     * are refused.
     *
     * @param array<array-key, mixed>                      $form
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $accepted
     */
    #[Test]
    #[DataProvider('provideMessageFieldsTheMethodDoesNotTake')]
    public function itRefusesAMessageFieldTheMethodDoesNotTake(array $form, array $accepted): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The form carries a message field the method does not take (B-1).');

        // When
        FormFields::read($form, $accepted, self::BOUND);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, non-empty-list<'SAMLRequest'|'SAMLResponse'>}>
     */
    public static function provideMessageFieldsTheMethodDoesNotTake(): iterable
    {
        yield 'a SAMLResponse given to authnRequest()' => [['SAMLResponse' => 'PHg+'], ['SAMLRequest']];
        yield 'a SAMLRequest given to response()' => [['SAMLRequest' => 'PHg+'], ['SAMLResponse']];
    }

    /**
     * §9.2 row 8, B-1, section 6.2 step 1: one of the three fields of the binding holding anything but a string, an
     * array as PHP's parser makes of a field named "SAMLResponse[]", is refused.
     *
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideFieldsThatAreNotStrings')]
    public function itRefusesAFieldOfTheBindingThatIsNotAString(array $form): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('A field of the binding is not a string, an array for instance (B-1).');

        // When
        FormFields::read($form, ['SAMLRequest', 'SAMLResponse'], self::BOUND);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideFieldsThatAreNotStrings(): iterable
    {
        yield 'SAMLResponse[]' => [['SAMLResponse' => ['PHg+']]];
        yield 'SAMLRequest[]' => [['SAMLRequest' => ['PHg+']]];
        yield 'RelayState[], next to a SAMLResponse' => [['SAMLResponse' => 'PHg+', 'RelayState' => ['state']]];
        yield 'SAMLRequest, an integer' => [['SAMLRequest' => 1]];
        yield 'SAMLResponse, null' => [['SAMLResponse' => null]];
    }

    /**
     * §9.2 row 29, section 8, section 6.2 step 1, SAML Bindings §3.5.4: SigAlg or Signature in a form, whatever their
     * value, is refused by name, before the message field is read.
     *
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideFormsWithADetachedSignature')]
    public function itRefusesADetachedSignatureInAForm(array $form): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('SigAlg or Signature in a form is refused: HTTP-POST carries no detached signature (section 8).');

        // When
        FormFields::read($form, ['SAMLResponse'], self::BOUND);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideFormsWithADetachedSignature(): iterable
    {
        $signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

        yield 'SigAlg and Signature' => [[
            'SAMLResponse' => 'PHg+',
            'SigAlg' => $signatureAlgorithm,
            'Signature' => 'AA==',
        ]];
        yield 'SigAlg alone' => [['SAMLResponse' => 'PHg+', 'SigAlg' => $signatureAlgorithm]];
        yield 'Signature alone' => [['SAMLResponse' => 'PHg+', 'Signature' => 'AA==']];
        yield 'an empty Signature' => [['SAMLResponse' => 'PHg+', 'Signature' => '']];
        yield 'Signature[]' => [['SAMLResponse' => 'PHg+', 'Signature' => ['AA==']]];
        yield 'SigAlg, without message field' => [['SigAlg' => $signatureAlgorithm]];
    }

    /**
     * §9.2 row 23, B-7, section 6.2 step 2, section 7: a message field one byte longer than maxFormValueBytes is
     * refused before anything decodes it, the bound named.
     */
    #[Test]
    public function itRefusesAMessageFieldOverTheBound(): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The message field is longer than maxFormValueBytes, 6 bytes (B-7).');

        // When
        FormFields::read(['SAMLRequest' => 'PHg+PHg'], ['SAMLRequest'], 6);
    }

    /**
     * B-7, section 6.2 step 2, section 7: a message field of exactly maxFormValueBytes is read.
     */
    #[Test]
    public function itReadsAMessageFieldOfExactlyTheBound(): void
    {
        // When
        $fields = FormFields::read(['SAMLRequest' => 'PHg+PHk+'], ['SAMLRequest'], 8);

        // Then
        static::assertSame('PHg+PHk+', $fields->message);
    }

    /**
     * §9.2 row 7, B-8, section 6.2 step 2: an empty SAMLRequest or SAMLResponse is refused.
     *
     * @param array<array-key, mixed> $form
     */
    #[Test]
    #[DataProvider('provideEmptyMessageFields')]
    public function itRefusesAnEmptyMessageField(array $form): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The message field is empty (B-8).');

        // When
        FormFields::read($form, ['SAMLRequest', 'SAMLResponse'], self::BOUND);
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function provideEmptyMessageFields(): iterable
    {
        yield 'an empty SAMLRequest' => [['SAMLRequest' => '']];
        yield 'an empty SAMLResponse' => [['SAMLResponse' => '', 'RelayState' => 'state']];
    }

    /**
     * §9.3 row 5, B-9, section 6.2 step 3, section 8, SAML Bindings §3.5.3: a RelayState of exactly 1 024 bytes, the
     * exception section 8 makes to the 80 bytes of the binding, is kept as given.
     */
    #[Test]
    public function itKeepsARelayStateOf1024Bytes(): void
    {
        // Given
        $relayState = str_repeat('€', 341) . '%';

        // When
        $fields = FormFields::read(
            ['SAMLResponse' => 'PHg+', 'RelayState' => $relayState],
            ['SAMLResponse'],
            self::BOUND,
        );

        // Then
        static::assertSame($relayState, $fields->relayState);
    }

    /**
     * §9.2 row 16, B-9, section 6.2 step 3, section 8, SAML Bindings §3.5.3: a RelayState of 1 025 bytes in a form is
     * refused.
     */
    #[Test]
    public function itRefusesARelayStateOver1024Bytes(): void
    {
        // Then
        $this->expectException(InvalidRelayState::class);
        $this->expectExceptionMessageIs('The RelayState is longer than 1024 bytes (B-9).');

        // When
        FormFields::read(
            ['SAMLResponse' => 'PHg+', 'RelayState' => str_repeat('€', 341) . '%+'],
            ['SAMLResponse'],
            self::BOUND,
        );
    }

    /**
     * §9.2 row 16, B-9, section 6.2 step 3, section 12: an empty RelayState in a form is refused.
     */
    #[Test]
    public function itRefusesAnEmptyRelayState(): void
    {
        // Then
        $this->expectException(InvalidRelayState::class);
        $this->expectExceptionMessageIs('The RelayState is empty (B-9).');

        // When
        FormFields::read(['SAMLResponse' => 'PHg+', 'RelayState' => ''], ['SAMLResponse'], self::BOUND);
    }
}
