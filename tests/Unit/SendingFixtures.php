<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function array_filter;
use function array_values;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\PostForm;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use DateTimeImmutable;
use function explode;
use LogicException;
use function str_repeat;

/**
 * What the tests of HTTP-Redirect and HTTP-POST sent share (sections 6.3, 6.4, 9.1, 9.2, 9.3): the messages the senders
 * write, as the model's message objects. Over HTTP-Redirect, each is the very message whose writer's unsigned document
 * is a fixture file, so that what the sender carries is compared with what the writer wrote (B-6, B-10): the
 * AuthnRequest of the service provider to the identity provider, behaviour/authn-request-written-for-http-redirect.xml,
 * written by saml2-model's AuthnRequestWriter at 9c833c5 with no Signing; the LogoutRequest of the identity provider
 * and the LogoutResponse of the service provider, the two logout documents of ReceptionFixtures, which that writer
 * writes byte for byte. Over HTTP-POST, the same three, and the identity provider's response to the AuthnRequest at
 * the service provider's assertion consumer service, its assertion of the parts the profile requires (the values of
 * saml2-model's ResponseWriterFixtures at 9c833c5, its IDs fixed), and its failure, Responder and AuthnFailed. A
 * Signing holds a test key; the parties and the validators are those of ReceptionFixtures.
 *
 * @phpstan-type Message 'an unsigned AuthnRequest'|'an AuthnRequest'|'a LogoutRequest'|'a LogoutResponse'
 * @phpstan-type PostMessage Message|'a Response'|'a Response signed whole'|'an unsigned failure'|'a failure'
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
     * A RelayState of exactly 1 024 bytes once decoded, the bound of B-9 (section 8), every byte escaped on the wire:
     * 341 euro signs, three bytes each, then a slash, 3 072 characters percent-encoded, the longest RelayState a query
     * string of the package carries (section 7).
     */
    public static function longestRelayState(): string
    {
        return str_repeat('€', 341) . '/';
    }

    /**
     * The ID of the service provider's AuthnRequest, which the identity provider's response answers.
     */
    public const string AUTHN_REQUEST_ID = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';

    public const string RESPONSE_ID = '_8f2e4d6c1b3a5f7e9d0c2b4a6f8e1d3c5b7a9f0e';

    public const string ASSERTION_ID = '_3c5e7a9b1d2f4e6a8c0b1d3f5e7a9c2b4d6f8e0a';

    public const string FAILURE_ID = '_9d1f3b5a7c2e4d6f8a0b2c4e6a8d0f1b3c5e7a9d';

    /**
     * The service provider's AuthnRequest to the single sign-on service, or to $destination.
     */
    private static function authnRequest(?string $destination = self::SSO): AuthnRequest
    {
        return new AuthnRequest(
            self::AUTHN_REQUEST_ID,
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
     * The identity provider's response to the AuthnRequest, Success, at the assertion consumer service or at
     * $destination, issued when the AuthnRequest is.
     */
    private static function response(?string $destination = self::ACS): Response
    {
        return new Response(
            self::RESPONSE_ID,
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://idp.example.com/saml'),
            $destination,
            self::AUTHN_REQUEST_ID,
            new Status(StatusCode::Success),
            self::assertion(),
        );
    }

    /**
     * The assertion of the response: an unspecified NameID, a bearer confirmation to the assertion consumer service
     * answering the AuthnRequest, Conditions without window holding the service provider as audience, an
     * authentication statement with its SessionIndex.
     */
    private static function assertion(): Assertion
    {
        return new Assertion(
            self::ASSERTION_ID,
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://idp.example.com/saml'),
            new NameId('alice'),
            new SubjectConfirmation(
                self::ACS,
                new DateTimeImmutable('2026-10-01T12:05:00Z'),
                self::AUTHN_REQUEST_ID,
                null,
            ),
            new Conditions(null, null, [['https://sp.example.com/saml']], false),
            new AuthnStatement(
                new DateTimeImmutable('2026-10-01T11:59:30Z'),
                '_session',
                null,
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ),
            [],
        );
    }

    /**
     * The identity provider's failure to the AuthnRequest, Responder and AuthnFailed, without assertion, at the
     * assertion consumer service or at $destination.
     */
    private static function failure(?string $destination = self::ACS): Response
    {
        return new Response(
            self::FAILURE_ID,
            new DateTimeImmutable('2026-10-01T12:00:00Z'),
            new Issuer('https://idp.example.com/saml'),
            $destination,
            self::AUTHN_REQUEST_ID,
            new Status(StatusCode::Responder, SecondLevelStatusCode::AuthnFailed),
            null,
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
     * The post sender under the default bounds of section 7, or under $limits.
     */
    private static function postSender(?BindingLimits $limits = null): PostSender
    {
        return new PostSender($limits ?? new BindingLimits());
    }

    /**
     * The form the post sender writes for $message: the AuthnRequest unsigned or signed by the service provider, the
     * LogoutRequest signed by the identity provider, the LogoutResponse signed by the service provider, the response
     * signed by the identity provider, its assertion or the whole, its failure unsigned or signed, each under
     * $algorithm, or by the key of $signing when one is given; with $relayState, under $limits or the default bounds.
     *
     * @param PostMessage $message
     */
    private static function post(
        string $message,
        ?string $relayState = null,
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
        ?BindingLimits $limits = null,
        ?Signing $signing = null,
    ): PostForm {
        $sender = self::postSender($limits);

        return match ($message) {
            'an unsigned AuthnRequest' => $sender->authnRequest(self::authnRequest(), null, $relayState),
            'an AuthnRequest' => $sender->authnRequest(
                self::authnRequest(),
                $signing ?? self::signing('sp', $algorithm),
                $relayState,
            ),
            'a LogoutRequest' => $sender->logoutRequest(
                self::logoutRequest(),
                $signing ?? self::signing('idp', $algorithm),
                $relayState,
            ),
            'a LogoutResponse' => $sender->logoutResponse(
                self::logoutResponse(),
                $signing ?? self::signing('sp', $algorithm),
                $relayState,
            ),
            'a Response' => $sender->response(
                self::response(),
                $signing ?? self::signing('idp', $algorithm),
                SignedParts::Assertion,
                $relayState,
            ),
            'a Response signed whole' => $sender->response(
                self::response(),
                $signing ?? self::signing('idp', $algorithm),
                SignedParts::AssertionAndResponse,
                $relayState,
            ),
            'an unsigned failure' => $sender->failure(self::failure(), null, $relayState),
            'a failure' => $sender->failure(self::failure(), $signing ?? self::signing('idp', $algorithm), $relayState),
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
