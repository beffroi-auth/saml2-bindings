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
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Section 5.2, section 6.1 steps 1 to 11, section 6.2 steps 1 to 6, B-2, B-5, B-12: one query string or one form read
 * whole, the unverified message, RelayState, the binding and, over a signed query string, the detached signature whose
 * octets are those of that very query string; a form carries none, and a response travels in a form only. SAML
 * Bindings §3.4.4.1, §3.5.4.
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

    /**
     * B-12, section 5.2, SAML Profiles §4.1.2: the reception of a query string at the assertion consumer service, which
     * would read a response over HTTP-Redirect, is a programming error, refused before the query string is read.
     */
    #[Test]
    public function itNeverReadsAResponseFromAQueryString(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLResponse', self::fixture(self::RESPONSE))->toString();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A response never travels over HTTP-Redirect (B-12).');

        // When
        Reception::ofQueryString($query, Service::AssertionConsumer, SamlLoader::create(), 8_192, 65_536);
    }

    /**
     * B-5, section 6.2 steps 1 to 6, SAML Bindings §3.5.4: a form read whole is the unverified message it carries, its
     * RelayState as given, over HTTP-POST, and no detached signature.
     */
    #[Test]
    public function itReadsAFormWhole(): void
    {
        // Given
        $form = self::form('SAMLResponse', self::fixture(self::RESPONSE), 'a state');

        // When
        $reception = Reception::ofForm($form, Service::AssertionConsumer, SamlLoader::create(), 1_572_864);

        // Then
        static::assertInstanceOf(UnverifiedResponse::class, $reception->message);
        static::assertSame(
            ['https://idp.example.com/saml', self::RESPONSE_REQUEST_ID, 'a state', Binding::HttpPost, null],
            [
                $reception->message->issuer,
                $reception->message->inResponseTo,
                $reception->relayState,
                $reception->binding,
                $reception->signature,
            ],
        );
    }

    /**
     * §9.2 row 23, B-7, section 6.2 step 2: the message field of a form is bounded by the bound it is given, named in
     * the refusal.
     */
    #[Test]
    public function itBoundsTheMessageFieldByTheBoundItIsGiven(): void
    {
        // Given
        $form = self::form('SAMLRequest', self::fixture(self::AUTHN_REQUEST));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The message field is longer than maxFormValueBytes, 100 bytes (B-7).');

        // When
        Reception::ofForm($form, Service::SingleSignOn, SamlLoader::create(), 100);
    }
}
