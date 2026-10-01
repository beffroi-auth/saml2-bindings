<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_filter;
use function array_values;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use DateTimeImmutable;
use function explode;
use LogicException;

/**
 * What the tests of HTTP-Redirect sent share (sections 6.3, 9.1, 9.2, 9.3): the three messages the sender writes, as
 * the model's message objects, each the very message whose writer's unsigned document is a fixture file, so that what
 * the sender carries is compared with what the writer wrote (B-6, B-10): the AuthnRequest of the service provider to
 * the identity provider, behaviour/authn-request-written-for-http-redirect.xml, written by saml2-model's
 * AuthnRequestWriter at 9c833c5 with no Signing; the LogoutRequest of the identity provider and the LogoutResponse of
 * the service provider, the two logout documents of ReceptionFixtures, which that writer writes byte for byte. A
 * Signing holds a test key; the parties and the validators are those of ReceptionFixtures.
 *
 * @phpstan-type Message 'an unsigned AuthnRequest'|'an AuthnRequest'|'a LogoutRequest'|'a LogoutResponse'
 */
trait SendingFixtures
{
    use ReceptionFixtures;

    public const string AUTHN_REQUEST_WRITTEN = 'behaviour/authn-request-written-for-http-redirect.xml';

    /**
     * A RelayState of exactly 80 bytes once decoded (B-9): twenty euro signs, three bytes each, then every character
     * a query string reads or percent-encoding escapes, a space, &, =, +, /, ?, #, %, ;, and the four unreserved
     * characters other than letters and digits, ~, -, . and _.
     */
    public const string RELAY_STATE = '€€€€€€€€€€€€€€€€€€€€ &=+/?#%;~-._state00';

    /**
     * The service provider's AuthnRequest to the single sign-on service, or to $destination.
     */
    private static function authnRequest(?string $destination = self::SSO): AuthnRequest
    {
        return new AuthnRequest(
            '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b',
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://sp.example.com/saml'),
            $destination,
            'https://sp.example.com/saml/acs',
            null,
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        );
    }

    /**
     * The identity provider's LogoutRequest to the service provider's single logout service, or to $destination.
     */
    private static function logoutRequest(string $destination = self::SP_SLO): LogoutRequest
    {
        return new LogoutRequest(
            self::LOGOUT_REQUEST_ID,
            new DateTimeImmutable('2026-09-30T12:00:00Z'),
            new Issuer('https://idp.example.com/saml'),
            $destination,
            new DateTimeImmutable('2026-09-30T12:05:00Z'),
            new NameId(
                '_7a2f4c1d9e',
                NameIdFormat::Persistent,
                'https://idp.example.com/saml',
                'https://sp.example.com/saml',
            ),
            ['_session-1'],
            'urn:oasis:names:tc:SAML:2.0:logout:user',
        );
    }

    /**
     * The service provider's LogoutResponse to the identity provider's single logout service, or to $destination.
     */
    private static function logoutResponse(string $destination = self::IDP_SLO): LogoutResponse
    {
        return new LogoutResponse(
            '_6e2b1f8d0c4a5b3f9e7d2c1b0a9f8e7d6c5b4a3f',
            new DateTimeImmutable('2026-09-30T12:00:00Z'),
            new Issuer('https://sp.example.com/saml'),
            $destination,
            self::LOGOUT_REQUEST_ID,
            new Status(StatusCode::Success),
        );
    }

    /**
     * The identity provider of ReceptionFixtures, its single sign-on service at $location over HTTP-Redirect.
     */
    private static function identityProviderAt(string $location): IdentityProvider
    {
        return new IdentityProvider(
            'https://idp.example.com/saml',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, $location)],
            [new Endpoint(Binding::HttpRedirect, self::IDP_SLO)],
        );
    }

    /**
     * The Signing of the test key $key under $algorithm, without certificate: HTTP-Redirect carries no KeyInfo.
     *
     * @param 'idp'|'sp' $key
     */
    private static function signing(string $key, SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256): Signing
    {
        return new Signing(TestKeys::signingKey($key), $algorithm);
    }

    /**
     * The sender under the default bounds of section 7, or under $limits.
     */
    private static function sender(?BindingLimits $limits = null): RedirectSender
    {
        return new RedirectSender($limits ?? new BindingLimits());
    }

    /**
     * The URL the sender writes for $message: the AuthnRequest unsigned or signed by the service provider, the
     * LogoutRequest signed by the identity provider, the LogoutResponse signed by the service provider, each under
     * $algorithm, or by the key of $signing when one is given; with $relayState, to $destination or to the message's
     * own, under $limits or the default bounds.
     *
     * @param Message $message
     */
    private static function send(
        string $message,
        ?string $relayState = null,
        ?string $destination = null,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        ?BindingLimits $limits = null,
        ?Signing $signing = null,
    ): string {
        $sender = self::sender($limits);

        return match ($message) {
            'an unsigned AuthnRequest' => $sender->authnRequest(
                self::authnRequest($destination ?? self::SSO),
                null,
                $relayState,
            ),
            'an AuthnRequest' => $sender->authnRequest(
                self::authnRequest($destination ?? self::SSO),
                $signing ?? self::signing('sp', $algorithm),
                $relayState,
            ),
            'a LogoutRequest' => $sender->logoutRequest(
                self::logoutRequest($destination ?? self::SP_SLO),
                $signing ?? self::signing('idp', $algorithm),
                $relayState,
            ),
            'a LogoutResponse' => $sender->logoutResponse(
                self::logoutResponse($destination ?? self::IDP_SLO),
                $signing ?? self::signing('sp', $algorithm),
                $relayState,
            ),
        };
    }

    /**
     * Every signature algorithm this build signs and verifies: the three of PKCS#1 v1.5, and the three of RSASSA-PSS
     * on PHP 8.5 with OpenSSL 3.1 (dsig.md section 5.1).
     *
     * @return list<SignatureAlgorithm>
     */
    private static function algorithms(): array
    {
        return array_values(array_filter(
            SignatureAlgorithm::cases(),
            static fn (SignatureAlgorithm $algorithm): bool => $algorithm->isAvailable(),
        ));
    }

    /**
     * The query string of $url, what follows its first "?", as the consumer's peer receives it.
     */
    private static function queryString(string $url): string
    {
        return explode('?', $url, 2)[1] ?? throw new LogicException('A URL of the tests holds no query.');
    }

    /**
     * The query of $url, read back.
     */
    private static function query(string $url): RedirectQuery
    {
        return RedirectQuery::of(self::queryString($url));
    }
}
