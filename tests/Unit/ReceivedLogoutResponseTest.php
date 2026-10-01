<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 12, B-2, B-4, B-5, SAML Profiles §4.4.4.2: a LogoutResponse of the service provider received by the
 * identity provider over HTTP-Redirect, its query string signed with the "sp" test key: verified under the service
 * provider's keys before validateAuthenticatedByBinding(), and refused unsigned by the model's validate().
 */
final class ReceivedLogoutResponseTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * B-5, M-10: a signed LogoutResponse, its signature verified under the service provider's key, is accepted by the
     * binding's authentication, as the answer to the request it names.
     */
    #[Test]
    public function itAuthenticatesASignedResponseByTheBinding(): void
    {
        // Given
        $received = $this->received($this->query()->withRelayState('state')->signed());

        // When
        $accepted = $this->validate($received);

        // Then
        static::assertSame(
            [Authentication::Binding, '_6e2b1f8d0c4a5b3f9e7d2c1b0a9f8e7d6c5b4a3f', 'state'],
            [$accepted->authentication, $accepted->response->id, $received->relayState],
        );
    }

    /**
     * §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.2: an unsigned LogoutResponse over HTTP-Redirect is refused by the
     * model's validate().
     */
    #[Test]
    public function itRefusesAnUnsignedResponse(): void
    {
        // Given
        $received = $this->received($this->query());

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 14, B-1, B-2, SAML Bindings §3.4.4.1: the signature of a SAMLRequest carried over a SAMLResponse of the
     * same value is refused: the name of the message parameter is among the octets.
     */
    #[Test]
    public function itRefusesTheSignatureOfASamlRequestCarriedOverASamlResponse(): void
    {
        // Given
        $signedAsRequest = RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_RESPONSE))->signed();
        $query = RedirectQuery::none()
            ->with('SAMLResponse', $signedAsRequest->value('SAMLRequest'))
            ->with('SigAlg', $signedAsRequest->value('SigAlg'))
            ->with('Signature', $signedAsRequest->value('Signature'));
        $received = $this->received($query);

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 17, B-4, SAML Bindings §3.4.4.1: a LogoutResponse signed by a key the service provider's metadata does
     * not list is refused.
     */
    #[Test]
    public function itRefusesAKeyThePeerDoesNotList(): void
    {
        // Given
        $received = $this->received($this->query()->signed('idp'));

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 18, B-4, SAML Metadata §2.4.1.1: a signed LogoutResponse from a service provider whose metadata holds no
     * signing certificate is refused.
     */
    #[Test]
    public function itRefusesAPeerWithoutSigningCertificate(): void
    {
        // Given
        $received = $this->received($this->query()->signed());

        // Then
        $this->expectException(NoVerificationKey::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing certificate to verify the query string with (B-4).');

        // When
        $this->validate($received, self::serviceProviderOf([]));
    }

    /**
     * Section 5.2, B-5: a ReceivedLogoutResponse is built from the reception of a LogoutResponse and of no other message, a programming
     * error otherwise.
     */
    #[Test]
    #[DataProvider('provideReceptionsOfOtherMessages')]
    public function itRefusesTheReceptionOfAnotherMessage(Reception $reception): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A ReceivedLogoutResponse is built from the reception of a LogoutResponse (section 5.2).');

        // When
        new ReceivedLogoutResponse($reception);
    }

    /**
     * @return iterable<string, array{Reception}>
     */
    public static function provideReceptionsOfOtherMessages(): iterable
    {
        yield 'the reception of an AuthnRequest' => [self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST)),
            Service::SingleSignOn,
        )];
        yield 'the reception of a LogoutRequest' => [self::reception(
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST)),
            Service::SingleLogout,
        )];
        yield 'the reception of a Response, over HTTP-POST' => [self::formReception(
            'SAMLResponse',
            self::fixture(self::RESPONSE),
            Service::AssertionConsumer,
        )];
    }

    private function query(): RedirectQuery
    {
        return RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE));
    }

    private function received(RedirectQuery $query): ReceivedLogoutResponse
    {
        $received = self::receiver()->logoutMessage($query->toString());
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        return $received;
    }

    /**
     * $received validated as the identity provider at its single logout service, from the service provider $sp or the
     * one of the fixtures, as the answer to the LogoutRequest of the fixtures.
     */
    private function validate(
        ReceivedLogoutResponse $received,
        ?ServiceProvider $sp = null,
    ): AcceptedLogoutResponse {
        return $received->validate(
            self::logoutResponseValidator(),
            $sp ?? self::serviceProvider(),
            self::identityProvider(),
            self::IDP_SLO,
            self::LOGOUT_REQUEST_ID,
        );
    }
}
