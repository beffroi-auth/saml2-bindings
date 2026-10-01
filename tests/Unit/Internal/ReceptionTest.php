<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Unit\ReceptionFixtures;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.2, section 6.1 steps 1 to 11, B-2, B-5: one query string read whole, the unverified message, RelayState,
 * the binding and the detached signature whose octets are those of that very query string. SAML Bindings §3.4.4.1.
 */
final class ReceptionTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * B-2, B-5, SAML Bindings §3.4.4.1: the octets of the signature a reception holds are those of the query string
     * whose message it read, its RelayState decoded, over HTTP-Redirect.
     */
    #[Test]
    public function itReadsAQueryStringWhole(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))
            ->withRelayState('a state')
            ->signed();

        // When
        $reception = self::reception($query, Service::SingleSignOn);

        // Then
        static::assertSame(
            ['https://sp.example.com/saml', 'a state', Binding::HttpRedirect, $query->octets()],
            [
                $reception->message->issuer,
                $reception->relayState,
                $reception->binding,
                $reception->signature?->octets->bytes,
            ],
        );
    }

    /**
     * B-5, SAML Bindings §3.4.4.1: an unsigned query string gives a reception without detached signature.
     */
    #[Test]
    public function itHasNoSignatureWithoutOne(): void
    {
        // When
        $reception = self::reception(
            RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE)),
            Service::SingleLogout,
        );

        // Then
        static::assertInstanceOf(UnverifiedLogoutResponse::class, $reception->message);
        static::assertNull($reception->signature);
    }

    /**
     * §9.2 row 23, B-7, section 6.1 step 1, SAML Bindings §3.4.4: the query string is bounded by the bound it is given,
     * named in the refusal.
     */
    #[Test]
    public function itBoundsTheQueryStringByTheBoundItIsGiven(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST))->toString();

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The query string is longer than maxQueryStringBytes, 100 bytes (B-7).');

        // When
        Reception::ofQueryString($query, Service::SingleSignOn, SamlLoader::create(), 100, strlen($query) * 4);
    }
}
