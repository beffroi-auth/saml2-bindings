<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 step 12, B-4, B-5, SAML Profiles §4.4.4.1: a LogoutRequest of the identity provider received by the
 * service provider over HTTP-Redirect, its query string signed with the "idp" test key: verified under the identity
 * provider's keys before validateAuthenticatedByBinding(), and refused unsigned by the model's validate().
 */
final class ReceivedLogoutRequestTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * B-5: a signed LogoutRequest, its signature verified under the identity provider's key, is accepted by the
     * binding's authentication.
     */
    #[Test]
    public function itAuthenticatesASignedRequestByTheBinding(): void
    {
        // Given
        $received = $this->received($this->query()->withRelayState('state')->signed('idp'));

        // When
        $accepted = $this->validate($received);

        // Then
        static::assertSame(
            [Authentication::Binding, '_5d1a0e7c9b3f4a2e8d6c1b0a9f8e7d6c5b4a3f2e', 'state'],
            [$accepted->authentication, $accepted->request->id, $received->relayState],
        );
    }

    /**
     * §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.1: an unsigned LogoutRequest over HTTP-Redirect is refused by the
     * model's validate().
     */
    #[Test]
    public function itRefusesAnUnsignedRequest(): void
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
     * §9.2 row 17, B-4, SAML Bindings §3.4.4.1: a LogoutRequest signed by a key the identity provider's metadata does
     * not list is refused.
     */
    #[Test]
    public function itRefusesAKeyThePeerDoesNotList(): void
    {
        // Given
        $received = $this->received($this->query()->signed('sp'));

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $this->validate($received);
    }

    /**
     * §9.2 row 18, B-4, SAML Metadata §2.4.1.1: a signed LogoutRequest from an identity provider whose metadata holds
     * no signing certificate is refused.
     */
    #[Test]
    public function itRefusesAPeerWithoutSigningCertificate(): void
    {
        // Given
        $received = $this->received($this->query()->signed('idp'));

        // Then
        $this->expectException(NoVerificationKey::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing certificate to verify the query string with (B-4).');

        // When
        $this->validate($received, self::identityProviderOf([]));
    }

    /**
     * Section 5.2, section 6.2 step 7, SAML Profiles §4.4.4.1: a request built without a detached signature, as
     * HTTP-POST will build it, goes to the model's validate(), which requires its XML signature.
     */
    #[Test]
    public function itValidatesARequestCarriedWithoutDetachedSignature(): void
    {
        // Given
        $received = new ReceivedLogoutRequest(
            UnverifiedLogoutRequest::of(SamlLoader::create()->load(self::fixture(self::LOGOUT_REQUEST))),
            null,
            Binding::HttpPost,
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $this->validate($received);
    }

    private function query(): RedirectQuery
    {
        return RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST));
    }

    private function received(RedirectQuery $query): ReceivedLogoutRequest
    {
        $received = self::receiver()->logoutMessage($query->toString());
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        return $received;
    }

    /**
     * $received validated as the service provider at its single logout service, from the identity provider $idp or
     * the one of the fixtures.
     */
    private function validate(
        ReceivedLogoutRequest $received,
        ?IdentityProvider $idp = null,
    ): AcceptedLogoutRequest {
        return $received->validate(
            self::logoutRequestValidator(),
            $idp ?? self::identityProvider(),
            self::serviceProvider(),
            self::SP_SLO,
        );
    }
}
