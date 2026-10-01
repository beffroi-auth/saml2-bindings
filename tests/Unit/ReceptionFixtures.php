<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Bindings\Tests\Unit\Internal\CodecFixtures;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use DateTimeImmutable;

/**
 * What the tests of HTTP-Redirect and HTTP-POST received share (sections 6.1, 6.2, 9.2, 9.3): the four messages, the
 * two parties and the model's validators with a clock frozen at the messages' IssueInstant. The messages are
 * saml2-model's, copied byte for byte from tests/Fixture/behaviour/ of its main at 9c833c5: an AuthnRequest of the
 * service provider to the identity provider, signed with the "sp" test key; a LogoutRequest of the identity provider to
 * the service provider, signed with "idp"; a LogoutResponse of the service provider to the identity provider, signed
 * with "sp"; a samlp:Response of the identity provider to the service provider's assertion consumer service, answering
 * the request _request, its assertion signed with "idp", response-signed-assertion-accepted.xml. The hostile
 * documents of tests/Fixture/hostile/ are copies too, renamed for the refusal they exist for: the AuthnRequest signed
 * in XML is the model's behaviour/authn-request-signed.xml, the samlp:Response its
 * behaviour/response-signed-assertion-accepted.xml; the DOCTYPE is the unsigned AuthnRequest with one line added.
 */
trait ReceptionFixtures
{
    use CodecFixtures;

    public const string AUTHN_REQUEST = 'behaviour/authn-request-unsigned.xml';

    public const string LOGOUT_REQUEST = 'behaviour/logout-request-written-for-http-redirect.xml';

    public const string LOGOUT_RESPONSE = 'behaviour/logout-response-written-for-http-redirect.xml';

    public const string RESPONSE = 'behaviour/response-signed-assertion-accepted.xml';

    /**
     * The ID of the AuthnRequest the response of RESPONSE answers.
     */
    public const string RESPONSE_REQUEST_ID = '_request';

    /**
     * The ID of the LogoutRequest the LogoutResponse answers.
     */
    public const string LOGOUT_REQUEST_ID = '_5d1a0e7c9b3f4a2e8d6c1b0a9f8e7d6c5b4a3f2e';

    public const string SSO = 'https://idp.example.com/saml/sso';

    public const string IDP_SLO = 'https://idp.example.com/saml/slo';

    public const string SP_SLO = 'https://sp.example.com/saml/slo';

    public const string ACS = 'https://sp.example.com/saml/acs';

    private static function receiver(): RedirectReceiver
    {
        return new RedirectReceiver(SamlLoader::create());
    }

    private static function postReceiver(): PostReceiver
    {
        return new PostReceiver(SamlLoader::create());
    }

    /**
     * The fields of a form carrying $message, base64-encoded on one line, in $field, then $relayState when given, as a
     * browser posts them and PHP's parser gives them to the consumer (section 6.8).
     *
     * @return array<array-key, mixed>
     */
    private static function form(string $field, string $message, ?string $relayState = null): array
    {
        return BrowserForm::posted(
            $relayState === null
                ? [[$field, base64_encode($message)]]
                : [
                    [$field,       base64_encode($message)],
                    ['RelayState', $relayState],
                ],
        );
    }

    /**
     * $query read whole for $service under the default bounds of section 7, as RedirectReceiver reads it.
     */
    private static function reception(RedirectQuery $query, Service $service): Reception
    {
        return Reception::ofQueryString($query->toString(), $service, SamlLoader::create(), 8_192, 65_536);
    }

    /**
     * The form carrying $message in $field read whole for $service under the default bound of section 7, as
     * PostReceiver reads it.
     */
    private static function formReception(string $field, string $message, Service $service): Reception
    {
        return Reception::ofForm(self::form($field, $message), $service, SamlLoader::create(), 1_572_864);
    }

    /**
     * The service provider, its signing certificate the "sp" test key, its requests unsigned by its metadata.
     */
    private static function serviceProvider(): ServiceProvider
    {
        return self::serviceProviderOf([TestKeys::certificate('sp')]);
    }

    /**
     * The service provider, its signing certificates $certificates, its requests unsigned by its metadata.
     *
     * @param list<string> $certificates
     */
    private static function serviceProviderOf(array $certificates): ServiceProvider
    {
        return new ServiceProvider(
            'https://sp.example.com/saml',
            $certificates,
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ACS, 0, true)]),
            [new Endpoint(Binding::HttpRedirect, self::SP_SLO)],
        );
    }

    /**
     * The service provider whose metadata says AuthnRequestsSigned (SAML Metadata §2.4.4).
     */
    private static function serviceProviderSigningItsRequests(): ServiceProvider
    {
        return new ServiceProvider(
            'https://sp.example.com/saml',
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ACS, 0, true)]),
            [new Endpoint(Binding::HttpRedirect, self::SP_SLO)],
            [],
            true,
        );
    }

    /**
     * The identity provider, its signing certificate the "idp" test key.
     */
    private static function identityProvider(): IdentityProvider
    {
        return self::identityProviderOf([TestKeys::certificate('idp')]);
    }

    /**
     * @param list<string> $certificates
     */
    private static function identityProviderOf(array $certificates): IdentityProvider
    {
        return new IdentityProvider(
            'https://idp.example.com/saml',
            $certificates,
            [],
            [new Endpoint(Binding::HttpRedirect, self::SSO)],
            [new Endpoint(Binding::HttpRedirect, self::IDP_SLO)],
        );
    }

    /**
     * The AuthnRequest validator, its clock at the request's IssueInstant.
     */
    private static function authnRequestValidator(): AuthnRequestValidator
    {
        return new AuthnRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-10-01T12:00:00Z')),
        );
    }

    /**
     * The LogoutRequest validator, its clock at the request's IssueInstant.
     */
    private static function logoutRequestValidator(): LogoutRequestValidator
    {
        return new LogoutRequestValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
        );
    }

    /**
     * The LogoutResponse validator, its clock at the response's IssueInstant.
     */
    private static function logoutResponseValidator(): LogoutResponseValidator
    {
        return new LogoutResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable('2026-09-30T12:00:00Z')),
        );
    }

    /**
     * The response validator of the service provider, its clock at $now, the IssueInstant of the response of RESPONSE
     * by default, and a replay guard of its own.
     */
    private static function responseValidator(string $now = '2026-09-30T12:00:00Z'): ResponseValidator
    {
        return new ResponseValidator(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable($now)),
            new InMemoryReplayGuard(),
        );
    }

    /**
     * What the service provider expects of a response to the AuthnRequest $requestId, received at its assertion
     * consumer service, for its entity ID.
     */
    private static function expectedResponse(string $requestId = self::RESPONSE_REQUEST_ID): ExpectedResponse
    {
        return ExpectedResponse::toRequest($requestId, self::ACS, 'https://sp.example.com/saml');
    }
}
