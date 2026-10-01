<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_keys;
use function base64_decode;
use function base64_encode;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\SigningKeyInterface;
use function get_class_methods;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 6.4, B-7, B-9, B-10, B-12: what PostSender writes, read back from the PostForm it returns with PHP's own
 * decoder, and what it refuses before it writes anything a receiver would refuse: the HTTP-POST rows of sections 9.2
 * and 9.3 that are the sender's. That every form it writes is received, verified and validated is PostRoundTripTest's.
 * SAML Bindings §3.5.4.
 *
 * @phpstan-import-type PostMessage from SendingFixtures
 */
final class PostSenderTest extends TestCase
{
    use SendingFixtures;

    /**
     * §9.3 row 12, section 6.4 step 4, SAML Bindings §3.5.4: the form holds SAMLRequest or SAMLResponse, then
     * RelayState when given, in that order and nothing else, its action the message's Destination.
     *
     * @param PostMessage  $message
     * @param list<string> $names
     */
    #[Test]
    #[DataProvider('provideForms')]
    public function itWritesTheFieldsInTheOrderOfTheBinding(
        string $message,
        ?string $relayState,
        string $action,
        array $names,
    ): void {
        // When
        $form = self::post($message, $relayState);

        // Then
        static::assertSame([$action, $names], [$form->action, array_keys($form->fields)]);
    }

    /**
     * @return iterable<string, array{PostMessage, ?string, string, list<string>}>
     */
    public static function provideForms(): iterable
    {
        yield 'an unsigned AuthnRequest' => ['an unsigned AuthnRequest', null, self::SSO, ['SAMLRequest']];
        yield 'an AuthnRequest, with RelayState' => [
            'an AuthnRequest',
            self::RELAY_STATE,
            self::SSO,
            ['SAMLRequest', 'RelayState'],
        ];
        yield 'a LogoutRequest, with RelayState' => [
            'a LogoutRequest',
            self::RELAY_STATE,
            self::SP_SLO,
            ['SAMLRequest', 'RelayState'],
        ];
        yield 'a LogoutResponse' => ['a LogoutResponse', null, self::IDP_SLO, ['SAMLResponse']];
        yield 'a Response, with RelayState' => [
            'a Response',
            self::RELAY_STATE,
            self::ACS,
            ['SAMLResponse', 'RelayState'],
        ];
        yield 'a failure' => ['a failure', null, self::ACS, ['SAMLResponse']];
    }

    /**
     * §9.3 row 12, B-9, section 6.7: RelayState is carried as given, nothing escaped for HTML nor for the URL: the page
     * and the browser are the consumer's.
     */
    #[Test]
    public function itCarriesRelayStateAsGiven(): void
    {
        // When
        $form = self::post('a LogoutResponse', '<b>"&\'</b> +%20');

        // Then
        static::assertSame('<b>"&\'</b> +%20', $form->fields['RelayState']);
    }

    /**
     * §9.3 row 12, B-10, section 6.4 steps 2 and 3, SAML Bindings §3.5.4: the message field is the base64, on one line
     * and padded, of the bytes Core's Serializer gives of the document the model's writer wrote with the Signing given,
     * never deflated: what the form carries is what the writer signed.
     *
     * @param PostMessage $message
     */
    #[Test]
    #[DataProvider('provideWrittenMessages')]
    public function itCarriesTheMessageTheWriterSigned(string $message, string $field, string $written): void
    {
        // When
        $form = self::post($message);

        // Then
        static::assertSame(base64_encode($written), $form->fields[$field]);
    }

    /**
     * @return iterable<string, array{PostMessage, string, string}>
     */
    public static function provideWrittenMessages(): iterable
    {
        $serializer = new Serializer();

        yield 'an unsigned AuthnRequest' => [
            'an unsigned AuthnRequest',
            'SAMLRequest',
            $serializer->serialize(new AuthnRequestWriter()->write(self::authnRequest(), null)),
        ];
        yield 'an AuthnRequest' => [
            'an AuthnRequest',
            'SAMLRequest',
            $serializer->serialize(new AuthnRequestWriter()->write(self::authnRequest(), self::signing('sp'))),
        ];
        yield 'a LogoutRequest' => [
            'a LogoutRequest',
            'SAMLRequest',
            $serializer->serialize(new LogoutRequestWriter()->write(self::logoutRequest(), self::signing('idp'))),
        ];
        yield 'a LogoutResponse' => [
            'a LogoutResponse',
            'SAMLResponse',
            $serializer->serialize(new LogoutResponseWriter()->write(self::logoutResponse(), self::signing('sp'))),
        ];
        yield 'a Response, its assertion signed' => [
            'a Response',
            'SAMLResponse',
            $serializer->serialize(new ResponseWriter()->write(self::response(), self::signing('idp'))),
        ];
        yield 'a Response signed whole' => [
            'a Response signed whole',
            'SAMLResponse',
            $serializer->serialize(new ResponseWriter()->write(
                self::response(),
                self::signing('idp'),
                SignedParts::AssertionAndResponse,
            )),
        ];
        yield 'an unsigned failure' => [
            'an unsigned failure',
            'SAMLResponse',
            $serializer->serialize(new ResponseWriter()->writeFailure(self::failure(), null)),
        ];
        yield 'a failure' => [
            'a failure',
            'SAMLResponse',
            $serializer->serialize(new ResponseWriter()->writeFailure(self::failure(), self::signing('idp'))),
        ];
    }

    /**
     * B-12, section 6.4 step 2, SAML Profiles §4.4.4.1: what a Signing is given for is signed in XML, the logout
     * messages always, so that the form carries a ds:Signature.
     *
     * @param PostMessage $message
     */
    #[Test]
    #[DataProvider('provideSignedMessages')]
    public function itSignsInXml(string $message, string $field): void
    {
        // When
        $form = self::post($message);

        // Then
        static::assertStringContainsString(
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
            (string) base64_decode($form->fields[$field], true),
        );
    }

    /**
     * @return iterable<string, array{PostMessage, string}>
     */
    public static function provideSignedMessages(): iterable
    {
        yield 'an AuthnRequest' => ['an AuthnRequest', 'SAMLRequest'];
        yield 'a LogoutRequest' => ['a LogoutRequest', 'SAMLRequest'];
        yield 'a LogoutResponse' => ['a LogoutResponse', 'SAMLResponse'];
        yield 'a Response' => ['a Response', 'SAMLResponse'];
        yield 'a failure' => ['a failure', 'SAMLResponse'];
    }

    /**
     * Section 6.4 step 1: the Destination is the action as it is, its own query among it, which the receiver never
     * reads: unlike a URL of HTTP-Redirect, nothing of it is refused.
     */
    #[Test]
    public function itPostsToTheDestinationAsItIs(): void
    {
        // Given
        $destination = self::SP_SLO . '?tenant=acme&SAMLRequest=x';

        // When
        $form = self::postSender()->logoutRequest(self::logoutRequest($destination), self::signing('idp'));

        // Then
        static::assertSame($destination, $form->action);
    }

    /**
     * §9.2 row 33, B-9, section 6.4 step 1, SAML Bindings §3.5.3: a RelayState of 81 bytes, or an empty one, given to
     * any method, is a programming error of the caller, refused before anything is written or signed: a key management
     * service is never called for a form the sender refuses by its arguments.
     *
     * @param PostMessage $message
     */
    #[Test]
    #[DataProvider('provideRelayStatesOutsideTheBounds')]
    public function itRefusesARelayStateOutsideItsBounds(string $message, string $relayState, string $refusal): void
    {
        // Given
        $signing = $this->uncalledSigning();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($refusal);

        // When
        self::post($message, $relayState, signing: $signing);
    }

    /**
     * @return iterable<string, array{PostMessage, string, string}>
     */
    public static function provideRelayStatesOutsideTheBounds(): iterable
    {
        $over = 'The RelayState is longer than 80 bytes (B-9).';
        $empty = 'The RelayState is empty (B-9).';

        yield 'an AuthnRequest, 81 bytes' => ['an AuthnRequest', self::RELAY_STATE . 'x', $over];
        yield 'a LogoutRequest, 81 bytes' => ['a LogoutRequest', self::RELAY_STATE . 'x', $over];
        yield 'a LogoutResponse, 81 bytes' => ['a LogoutResponse', self::RELAY_STATE . 'x', $over];
        yield 'a Response, 81 bytes' => ['a Response', self::RELAY_STATE . 'x', $over];
        yield 'a failure, 81 bytes' => ['a failure', self::RELAY_STATE . 'x', $over];
        yield 'an AuthnRequest, empty' => ['an AuthnRequest', '', $empty];
        yield 'a LogoutRequest, empty' => ['a LogoutRequest', '', $empty];
        yield 'a LogoutResponse, empty' => ['a LogoutResponse', '', $empty];
        yield 'a Response signed whole, empty' => ['a Response signed whole', '', $empty];
        yield 'a failure, empty' => ['a failure', '', $empty];
    }

    /**
     * §9.2 row 33, section 6.4 step 1, M-15: an AuthnRequest or a Response without Destination, the action of the
     * form, is a programming error of the caller, refused before its writer runs and before the key is called.
     *
     * @param 'authnRequest'|'response'|'failure' $method
     */
    #[Test]
    #[DataProvider('provideMessagesWithoutDestination')]
    public function itRefusesAMessageWithoutDestination(string $method, string $refusal): void
    {
        // Given
        $signing = $this->uncalledSigning();
        $sender = new PostSender();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($refusal);

        // When
        match ($method) {
            'authnRequest' => $sender->authnRequest(self::authnRequest(null), $signing),
            'response' => $sender->response(self::response(null), $signing),
            'failure' => $sender->failure(self::failure(null), $signing),
        };
    }

    /**
     * @return iterable<string, array{'authnRequest'|'response'|'failure', string}>
     */
    public static function provideMessagesWithoutDestination(): iterable
    {
        yield 'an AuthnRequest' => [
            'authnRequest',
            'The AuthnRequest holds no Destination, the action of the form (section 6.4).',
        ];
        yield 'a Response' => ['response', 'The Response holds no Destination, the action of the form (section 6.4).'];
        yield 'a failure' => ['failure', 'The Response holds no Destination, the action of the form (section 6.4).'];
    }

    /**
     * Section 6.4 step 2, M-15: what the model's writer refuses, a response of Success given to failure() or a failure
     * given to response(), is refused as the writer refuses it, a programming error of the caller.
     *
     * @param 'response'|'failure' $method
     */
    #[Test]
    #[DataProvider('provideResponsesTheWriterRefuses')]
    public function itLetsTheRefusalOfTheWriterThrough(string $method, string $refusal): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($refusal);

        // When
        match ($method) {
            'response' => self::postSender()->response(self::failure(), self::signing('idp')),
            'failure' => self::postSender()->failure(self::response(), self::signing('idp')),
        };
    }

    /**
     * @return iterable<string, array{'response'|'failure', string}>
     */
    public static function provideResponsesTheWriterRefuses(): iterable
    {
        yield 'a failure given to response()' => [
            'response',
            'The response carries no assertion: a failure is written by writeFailure() (section 6.6).',
        ];
        yield 'a response of Success given to failure()' => [
            'failure',
            'The response carries an assertion: a response whose status is Success is written by write() (section 6.6).',
        ];
    }

    /**
     * §9.2 row 34, B-7, section 6.4 step 3: a form whose message, once encoded, is one byte longer than
     * maxFormValueBytes, which the package's receiver would refuse, is refused, whatever the method.
     *
     * @param PostMessage $message
     */
    #[Test]
    #[DataProvider('provideEveryMessage')]
    public function itRefusesAMessageOverMaxFormValueBytes(string $message, string $field): void
    {
        // Given
        $bound = strlen(self::post($message)->fields[$field]) - 1;

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The message would be longer than maxFormValueBytes, '
        . $bound
        . ' bytes, once encoded, which the receiver refuses (B-7).');

        // When
        self::post($message, limits: new BindingLimits(maxFormValueBytes: $bound));
    }

    /**
     * @return iterable<string, array{PostMessage, string}>
     */
    public static function provideEveryMessage(): iterable
    {
        yield 'an unsigned AuthnRequest' => ['an unsigned AuthnRequest', 'SAMLRequest'];
        yield 'a LogoutRequest' => ['a LogoutRequest', 'SAMLRequest'];
        yield 'a LogoutResponse' => ['a LogoutResponse', 'SAMLResponse'];
        yield 'a Response signed whole' => ['a Response signed whole', 'SAMLResponse'];
        yield 'an unsigned failure' => ['an unsigned failure', 'SAMLResponse'];
    }

    /**
     * B-7, section 6.4 step 3, section 7: a message of exactly maxFormValueBytes once encoded is sent, and the package's
     * receiver, under the same bounds, reads it.
     */
    #[Test]
    public function itSendsAMessageOfExactlyMaxFormValueBytesWhichTheReceiverReads(): void
    {
        // Given
        $limits = new BindingLimits(maxFormValueBytes: strlen(self::post('a Response')->fields['SAMLResponse']));
        $form = self::post('a Response', limits: $limits);

        // When
        $received = new PostReceiver(SamlLoader::create(), $limits)->response(BrowserForm::submitted($form));

        // Then
        static::assertSame(self::AUTHN_REQUEST_ID, $received->response->inResponseTo);
    }

    /**
     * B-12, section 5.3: the sender has a method for each message HTTP-POST carries, a response among them, and no
     * other.
     */
    #[Test]
    public function itHasAMethodForEachMessage(): void
    {
        // When
        $methods = get_class_methods(PostSender::class);

        // Then
        static::assertSame(
            ['__construct', 'response', 'failure', 'authnRequest', 'logoutRequest', 'logoutResponse'],
            $methods,
        );
    }

    /**
     * A Signing whose key fails the test if the sender calls it.
     */
    private function uncalledSigning(): Signing
    {
        $key = $this->createMock(SigningKeyInterface::class);
        $key->expects($this->never())->method('sign');

        return new Signing($key);
    }
}
