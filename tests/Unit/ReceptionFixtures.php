<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
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
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use DateTimeImmutable;

/**
 * What the tests of HTTP-Redirect received share (sections 6.1, 9.2, 9.3): the three messages, the two parties and the
 * model's validators with a clock frozen at the messages' IssueInstant. The messages are saml2-model's, copied byte for
 * byte from tests/Fixture/behaviour/ of its main at 9c833c5: an AuthnRequest of the service provider to the identity
 * provider, signed with the "sp" test key; a LogoutRequest of the identity provider to the service provider, signed
 * with "idp"; a LogoutResponse of the service provider to the identity provider, signed with "sp". The hostile
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

    /**
     * The ID of the LogoutRequest the LogoutResponse answers.
     */
    public const string LOGOUT_REQUEST_ID = '_5d1a0e7c9b3f4a2e8d6c1b0a9f8e7d6c5b4a3f2e';

    public const string SSO = 'https://idp.example.com/saml/sso';

    public const string IDP_SLO = 'https://idp.example.com/saml/slo';

    public const string SP_SLO = 'https://sp.example.com/saml/slo';

    private static function receiver(): RedirectReceiver
    {
        return new RedirectReceiver(SamlLoader::create());
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
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 0, true)]),
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
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, 'https://sp.example.com/saml/acs', 0, true)]),
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
}
