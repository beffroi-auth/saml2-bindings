<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\Tests\Unit\ReceptionFixtures;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 6.1 steps 3 and 11, B-1, M-1: the message parameters each service of ours takes, and the model's unverified
 * message it reads, by service and by parameter. SAML Bindings §3.4.4.1.
 */
final class ServiceTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * Section 6.1 step 3, B-1, SAML Bindings §3.4.4.1: a single sign-on service takes a SAMLRequest, a single logout
     * service either message parameter.
     *
     * @param list<string> $messageParameters
     */
    #[Test]
    #[DataProvider('provideMessageParameters')]
    public function itTakesTheMessageParametersOfItsService(Service $service, array $messageParameters): void
    {
        // When / Then
        static::assertSame($messageParameters, $service->messageParameters());
    }

    /**
     * @return iterable<string, array{Service, list<string>}>
     */
    public static function provideMessageParameters(): iterable
    {
        yield 'a single sign-on service' => [Service::SingleSignOn, ['SAMLRequest']];
        yield 'a single logout service' => [Service::SingleLogout, ['SAMLRequest', 'SAMLResponse']];
    }

    /**
     * Section 6.1 step 11, M-1, SAML Bindings §3.4.4.1: the message read, an AuthnRequest at a single sign-on service, a
     * LogoutRequest in a SAMLRequest and a LogoutResponse in a SAMLResponse at a single logout service.
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     * @param class-string                 $class
     */
    #[Test]
    #[DataProvider('provideMessages')]
    public function itReadsTheMessageOfItsService(
        Service $service,
        string $messageParameter,
        string $fixture,
        string $class,
    ): void {
        // When
        $message = $service->read($messageParameter, SamlLoader::create()->load(self::fixture($fixture)));

        // Then
        static::assertInstanceOf($class, $message);
    }

    /**
     * @return iterable<string, array{Service, 'SAMLRequest'|'SAMLResponse', string, class-string}>
     */
    public static function provideMessages(): iterable
    {
        yield 'an AuthnRequest' => [
            Service::SingleSignOn,
            'SAMLRequest',
            self::AUTHN_REQUEST,
            UnverifiedAuthnRequest::class,
        ];
        yield 'a LogoutRequest' => [
            Service::SingleLogout,
            'SAMLRequest',
            self::LOGOUT_REQUEST,
            UnverifiedLogoutRequest::class,
        ];
        yield 'a LogoutResponse' => [
            Service::SingleLogout,
            'SAMLResponse',
            self::LOGOUT_RESPONSE,
            UnverifiedLogoutResponse::class,
        ];
    }
}
