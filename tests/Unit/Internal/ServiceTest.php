<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\Tests\Unit\ReceptionFixtures;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Sections 6.1 steps 3 and 11 and 6.2 steps 2 and 6, B-1, M-1: the message parameters each service of ours takes, and
 * the model's unverified message it reads, by service and by parameter. SAML Bindings §3.4.4.1, §3.5.4.
 */
final class ServiceTest extends TestCase
{
    use ReceptionFixtures;

    /**
     * Sections 6.1 step 3 and 6.2 step 2, B-1, SAML Bindings §3.4.4.1, §3.5.4: a single sign-on service takes a
     * SAMLRequest, a single logout service either message parameter, an assertion consumer service a SAMLResponse.
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
        yield 'an assertion consumer service' => [Service::AssertionConsumer, ['SAMLResponse']];
    }

    /**
     * Sections 6.1 step 11 and 6.2 step 6, M-1, SAML Bindings §3.4.4.1, §3.5.4: the message read, an AuthnRequest at a
     * single sign-on service, a LogoutRequest in a SAMLRequest and a LogoutResponse in a SAMLResponse at a single logout
     * service, a Response at an assertion consumer service.
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
        yield 'a Response' => [
            Service::AssertionConsumer,
            'SAMLResponse',
            self::RESPONSE,
            UnverifiedResponse::class,
        ];
    }
}
