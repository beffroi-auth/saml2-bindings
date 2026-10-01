<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Model\Exception\UnsuccessfulResponse;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 9.1 over HTTP-POST: every form PostSender writes, its fields posted by a browser and parsed by PHP as the
 * consumer receives them (sections 6.7, 6.8), received by PostReceiver, then validated by the model's validator of the
 * peer's role, the test keys of tests/Fixture/keys/ in the metadata and a clock frozen at the message's IssueInstant:
 * an AuthnRequest signed in XML under every algorithm this build has, and unsigned; a LogoutRequest and a
 * LogoutResponse, always signed (B-12); a response with its assertion signed, with the response signed too, and a
 * failure, signed and unsigned; each without RelayState and with one of exactly 80 bytes, returned as it was given
 * (B-9). The message carries its XML signatures, which the model verifies (B-5, M-2). SAML Bindings §3.5.4.
 */
final class PostRoundTripTest extends TestCase
{
    use SendingFixtures;

    /**
     * Section 9.1, B-5, M-2: an AuthnRequest the service provider signs in XML under each algorithm of the build,
     * posted to the single sign-on service, is authenticated by its XML signature and accepted, its RelayState
     * returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedAuthnRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()->authnRequest(self::authnRequest(), self::signing('sp', $algorithm), $relayState);
        $received = self::postReceiver()->authnRequest(BrowserForm::submitted($form));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::AUTHN_REQUEST_ID, $relayState, Binding::HttpPost],
            [$accepted->authentication, $accepted->request->id, $received->relayState, $received->binding],
        );
    }

    /**
     * Section 9.1, B-5, §9.3 row 7: an unsigned AuthnRequest, from a service provider whose metadata asks for no
     * signature, posted to the single sign-on service, is accepted with no authentication, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itAcceptsAnUnsignedAuthnRequest(?string $relayState): void
    {
        // Given
        $form = self::postSender()->authnRequest(self::authnRequest(), null, $relayState);
        $received = self::postReceiver()->authnRequest(BrowserForm::submitted($form));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::None, self::AUTHN_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, B-12, SAML Profiles §4.4.4.1: a LogoutRequest the identity provider signs in XML under each
     * algorithm of the build, posted to the service provider's single logout service, is authenticated by its XML
     * signature and accepted, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()->logoutRequest(self::logoutRequest(), self::signing('idp', $algorithm), $relayState);
        $received = self::postReceiver()->logoutMessage(BrowserForm::submitted($form));
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);

        // When
        $accepted = $received->validate(
            self::logoutRequestValidator(),
            self::identityProvider(),
            self::serviceProvider(),
            self::SP_SLO,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::LOGOUT_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, B-12, SAML Profiles §4.4.4.1: a LogoutResponse the service provider signs in XML under each
     * algorithm of the build, posted to the identity provider's single logout service, is authenticated by its XML
     * signature and accepted as the answer to the request it names, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutResponse(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $form = self::postSender()
            ->logoutResponse(self::logoutResponse(), self::signing('sp', $algorithm), $relayState);
        $received = self::postReceiver()->logoutMessage(BrowserForm::submitted($form));
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        // When
        $accepted = $received->validate(
            self::logoutResponseValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::IDP_SLO,
            self::LOGOUT_REQUEST_ID,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, self::logoutResponse()->id, $relayState],
            [$accepted->authentication, $accepted->response->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, M-2, SAML Profiles §4.1.4.5: a response the identity provider signs under each algorithm of
     * the build, its assertion alone or the response too, posted to the service provider's assertion consumer service,
     * is verified and accepted under the coverage asked, the assertion as it was written, its RelayState returned.
     *
     * @param 'a Response'|'a Response signed whole' $message
     */
    #[Test]
    #[DataProvider('provideResponses')]
    public function itAcceptsAResponse(
        string $message,
        SignatureAlgorithm $algorithm,
        ?string $relayState,
        SignatureCoverage $coverage,
    ): void {
        // Given
        $received = self::postReceiver()
            ->response(BrowserForm::submitted(self::post($message, $relayState, $algorithm)));

        // When
        $accepted = $received->validate(
            self::responseValidator('2026-10-01T12:00:00Z'),
            self::identityProvider(),
            self::expectedResponse(self::AUTHN_REQUEST_ID),
        );

        // Then
        static::assertEquals(
            [self::RESPONSE_ID, self::assertion(), $coverage, $relayState],
            [$accepted->responseId, $accepted->assertion, $accepted->coverage, $received->relayState],
        );
    }

    /**
     * @return iterable<string, array{'a Response'|'a Response signed whole', SignatureAlgorithm, ?string, SignatureCoverage}>
     */
    public static function provideResponses(): iterable
    {
        foreach (self::provideAlgorithmsAndRelayStates() as $name => [$algorithm, $relayState]) {
            yield 'the assertion signed, ' . $name => [
                'a Response',
                $algorithm,
                $relayState,
                SignatureCoverage::Assertion,
            ];
            yield 'the response signed too, ' . $name => [
                'a Response signed whole',
                $algorithm,
                $relayState,
                SignatureCoverage::AssertionAndResponse,
            ];
        }
    }

    /**
     * Section 9.1, M-13, SAML Profiles §4.1.4.2: a failure, signed by the identity provider or not, posted to the
     * service provider's assertion consumer service, is read and refused by the model as unsuccessful, its status
     * carried as it was written, its RelayState returned.
     *
     * @param 'an unsigned failure'|'a failure' $message
     */
    #[Test]
    #[DataProvider('provideFailures')]
    public function itReadsAFailure(string $message, ?string $relayState): void
    {
        // Given
        $received = self::postReceiver()->response(BrowserForm::submitted(self::post($message, $relayState)));

        // When
        try {
            $received->validate(
                self::responseValidator('2026-10-01T12:00:00Z'),
                self::identityProvider(),
                self::expectedResponse(self::AUTHN_REQUEST_ID),
            );
            static::fail('The failure is not reported.');
        } catch (UnsuccessfulResponse $failure) {
            // Then
            static::assertSame(
                [StatusCode::Responder, SecondLevelStatusCode::AuthnFailed, $relayState],
                [$failure->status->code, $failure->status->secondLevel, $received->relayState],
            );
        }
    }

    /**
     * @return iterable<string, array{'an unsigned failure'|'a failure', ?string}>
     */
    public static function provideFailures(): iterable
    {
        foreach (self::provideRelayStates() as $name => [$relayState]) {
            yield 'unsigned, ' . $name => ['an unsigned failure', $relayState];
            yield 'signed, ' . $name => ['a failure', $relayState];
        }
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm, ?string}>
     */
    public static function provideAlgorithmsAndRelayStates(): iterable
    {
        foreach (self::algorithms() as $algorithm) {
            foreach (self::provideRelayStates() as $name => [$relayState]) {
                yield sprintf('%s, %s', $algorithm->name, $name) => [$algorithm, $relayState];
            }
        }
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield 'without RelayState' => [null];
        yield 'with a RelayState of 80 bytes' => [self::RELAY_STATE];
    }
}
