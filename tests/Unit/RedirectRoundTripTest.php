<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function strlen;

/**
 * Section 9.1 over HTTP-Redirect: every URL RedirectSender writes, its query string received by RedirectReceiver, then
 * validated by the model's validator of the peer's role, the test keys of tests/Fixture/keys/ in the metadata and a
 * clock frozen at the message's IssueInstant: an AuthnRequest signed under every algorithm this build has, and
 * unsigned; a LogoutRequest and a LogoutResponse, always signed (B-12); each without RelayState, with one of exactly
 * 80 bytes and with one of 1 024 bytes, the bound of B-9 (section 8), every byte escaped, returned as it was given. Signed, the message is authenticated by the binding (B-5); unsigned, by
 * nothing, and accepted only because neither party's metadata asks for a signed request (M-2). SAML Bindings §3.4.4.1.
 *
 * @phpstan-import-type Message from SendingFixtures
 */
final class RedirectRoundTripTest extends TestCase
{
    use SendingFixtures;

    /**
     * Section 9.1, B-2, B-5, §9.3 row 7: an AuthnRequest the service provider signs under each algorithm of the build,
     * received at the single sign-on service, is authenticated by the binding and accepted, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedAuthnRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->authnRequest(self::authnRequest(), self::signing('sp', $algorithm), $relayState);
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, self::authnRequest()->id, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-5, §9.3 row 7: an unsigned AuthnRequest, from a service provider whose metadata asks for no
     * signature, is accepted with no authentication, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itAcceptsAnUnsignedAuthnRequest(?string $relayState): void
    {
        // Given
        $url = self::sender()->authnRequest(self::authnRequest(), null, $relayState);
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame(
            [Authentication::None, self::authnRequest()->id, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-2, B-5, B-12, SAML Profiles §4.4.4.1: a LogoutRequest the identity provider signs under each
     * algorithm of the build, received at the service provider's single logout service, is authenticated by the
     * binding and accepted, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutRequest(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->logoutRequest(self::logoutRequest(), self::signing('idp', $algorithm), $relayState);
        $received = self::receiver()->logoutMessage(self::queryString($url));
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
            [Authentication::Binding, self::LOGOUT_REQUEST_ID, $relayState],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * Section 9.1, B-2, B-5, B-12, SAML Profiles §4.4.4.1: a LogoutResponse the service provider signs under each
     * algorithm of the build, received at the identity provider's single logout service, is authenticated by the
     * binding and accepted as the answer to the request it names, its RelayState returned.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsAndRelayStates')]
    public function itAcceptsASignedLogoutResponse(SignatureAlgorithm $algorithm, ?string $relayState): void
    {
        // Given
        $url = self::sender()->logoutResponse(self::logoutResponse(), self::signing('sp', $algorithm), $relayState);
        $received = self::receiver()->logoutMessage(self::queryString($url));
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
            [Authentication::Binding, self::logoutResponse()->id, $relayState],
            [$accepted->authentication, $accepted->response->id, $received->relayState],
        );
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
        yield 'with a RelayState of 1 024 bytes, every byte escaped' => [self::longestRelayState()];
    }

    /**
     * §9.3 row 5, section 7, B-7, B-9: a RelayState of 1 024 bytes, the bound of B-9, every byte escaped, 3 072
     * characters on the wire, fits the signed query string of each message under the default maxQueryStringBytes, and
     * the receiver returns it as it was given.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideSignedMessages')]
    public function itCarriesTheLongestRelayStateUnderTheDefaultBound(string $message): void
    {
        // Given
        $url = self::send($message, self::longestRelayState());

        // When
        $received = match ($message) {
            'an AuthnRequest' => self::receiver()->authnRequest(self::queryString($url)),
            default => self::receiver()->logoutMessage(self::queryString($url)),
        };

        // Then
        static::assertSame(
            [3_072, true, self::longestRelayState()],
            [
                strlen(self::query($url)->value('RelayState')),
                strlen(self::queryString($url)) <= new BindingLimits()->maxQueryStringBytes,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{Message}>
     */
    public static function provideSignedMessages(): iterable
    {
        yield 'an AuthnRequest' => ['an AuthnRequest'];
        yield 'a LogoutRequest' => ['a LogoutRequest'];
        yield 'a LogoutResponse' => ['a LogoutResponse'];
    }

    /**
     * §9.3 row 3, section 6.1 step 2, section 6.3 step 6, M-8: an AuthnRequest whose Destination holds its own query,
     * as the Location of the identity provider's endpoint may, is received with that query skipped and unsigned, and
     * accepted at that very URL.
     */
    #[Test]
    public function itAcceptsAnAuthnRequestWhoseDestinationHoldsItsOwnQuery(): void
    {
        // Given
        $destination = self::SSO . '?tenant=acme';
        $url = self::sender()->authnRequest(self::authnRequest($destination), self::signing('sp'), 'state');
        $received = self::receiver()->authnRequest(self::queryString($url));

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProviderAt($destination),
            $destination,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $destination, 'state'],
            [$accepted->authentication, $accepted->request->destination, $received->relayState],
        );
    }
}
