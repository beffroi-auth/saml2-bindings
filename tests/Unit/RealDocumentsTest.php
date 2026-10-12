<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Bindings\Tests\Unit\Internal\CodecFixtures;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_pad;

/**
 * Section 9.4: the query strings and forms SimpleSAMLphp 2.5.3.1 and Keycloak 26.7.4 sent, bytes as received, read by
 * the receivers of this package and validated by the model with a clock frozen at their capture, under the metadata of
 * their sender as it was served (tests/Fixture/real/README.md).
 *
 * Three captures. On 30 September 2026, saml2-model's harness: its service provider for-model, under sign.authnrequest
 * and sign.logout, to saml2-model's identity provider. On 1 October 2026, this package's judge (section 9.5,
 * tests/Interop/simplesamlphp/README.md): capture.php, a login and a logout between SimpleSAMLphp's own two parties,
 * default-sp and its identity provider, as the installation configures them; and exchange.php, SimpleSAMLphp's two
 * parties and this package's roles, at http://localhost:8093/bindings/, whose metadata the exchange wrote with the test
 * keys: an identity provider, and three service providers which the identity provider answers differently at logout
 * (sp under sign.logout, sp-defaults under its defaults, sp-post over HTTP-POST under sign.logout).
 *
 * Keycloak 26.7.4, on 1 October 2026, by the judge's second target (tests/Interop/keycloak/README.md): capture.php, a
 * login and a logout between realm sp's broker "idp" and realm idp, as realms/ configures them; and exchange.php, realm
 * sp's broker "bindings" and realm idp configured by Keycloak's importers from the metadata of this package's roles, at
 * https://idp.saml2-bindings.test/ and https://sp.saml2-bindings.test/, written with the test keys. Realm keys are new
 * at every start of Keycloak: the metadata of the run, kept with its captures, verify them.
 */
final class RealDocumentsTest extends TestCase
{
    use CodecFixtures;

    private const string SP = 'http://localhost:8092/simplesaml/module.php/saml/sp/';

    private const string IDP = 'http://localhost:8091/simplesaml/module.php/saml/idp/';

    private const string MODEL = 'http://localhost:8083/model/';

    private const string BINDINGS = 'http://localhost:8093/bindings/';

    /**
     * The second at which saml2-model's exchange issued the query strings it kept, 30 September 2026.
     */
    private const string SEPTEMBER_30 = '2026-09-30T13:07:34Z';

    /**
     * The seconds at which the run of this package's judge kept on 1 October 2026 issued its captures: the login of
     * capture.php, then everything else, its logout and the whole exchange.
     */
    private const string OCTOBER_1_LOGIN = '2026-10-01T11:03:33Z';

    private const string OCTOBER_1 = '2026-10-01T11:03:34Z';

    /**
     * The second at which for-bindings issued its AuthnRequest carrying a ReturnTo of 105 bytes, the measure of the
     * exchange that followed.
     */
    private const string OCTOBER_1_LONG_RETURN_TO = '2026-10-01T11:03:37Z';

    private const string KEYCLOAK = 'http://localhost:8190/realms/';

    private const string KEYCLOAK_BINDINGS_IDP = 'https://idp.saml2-bindings.test/';

    private const string KEYCLOAK_BINDINGS_SP = 'https://sp.saml2-bindings.test/';

    /**
     * The second within which Keycloak's run kept on 1 October 2026 issued its captures, 11:37:35.702 to 11:37:37.181:
     * the capture between its two realms, then the exchange.
     */
    private const string KEYCLOAK_OCTOBER_1 = '2026-10-01T11:37:37Z';

    /**
     * Section 9.4, section 6.1, B-2, B-5, SAML Bindings §3.4.4.1: a signed AuthnRequest of a real service provider, its
     * signature over SAMLRequest, RelayState and SigAlg as they arrived verified under the key of its metadata, accepted
     * by the binding's authentication, its RelayState returned as decoded: SimpleSAMLphp's ReturnTo, Keycloak's broker
     * state of 78 bytes; and, beyond the 80 bytes of SAML Bindings §3.4.3, the exception of section 8 (B-9): a ReturnTo
     * of 105 bytes (finding F-5 of tests/Interop/simplesamlphp/README.md) and the state of 122 bytes the broker writes
     * for a client whose internal ID is not a UUID (finding K-4 of tests/Interop/keycloak/README.md), both refused on 1
     * October 2026 and accepted since B-9 reads up to 1 024 bytes (section 12).
     */
    #[Test]
    #[DataProvider('provideAuthnRequests')]
    public function itVerifiesAndValidatesTheSignedAuthnRequestsOfRealServiceProviders(
        string $query,
        string $capturedAt,
        string $serviceProvider,
        IdentityProvider $self,
        string $receivedAt,
        string $id,
        string $assertionConsumerService,
        string $relayState,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(self::fixture($query));

        // When
        $accepted = $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock($capturedAt)),
            self::serviceProvider($serviceProvider, $capturedAt),
            $self,
            $receivedAt,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, $assertionConsumerService, $relayState],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->assertionConsumerService->location,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, string, IdentityProvider, string, string, string, string}>
     */
    public static function provideAuthnRequests(): iterable
    {
        yield 'for-model to saml2-model, 30 September 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt',
            self::SEPTEMBER_30,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml',
            self::modelIdentityProvider(),
            self::MODEL . 'idp/sso',
            '_ef4cb04a9098a02745f19851d7b70d2e7712c1aa4d',
            'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/for-model',
            'http://localhost:8082/simplesaml/session.php',
        ];
        yield 'default-sp to its own identity provider, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-query-2026-10-01.txt',
            self::OCTOBER_1_LOGIN,
            'real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml',
            self::simpleSamlPhpIdentityProvider(),
            self::IDP . 'singleSignOnService',
            '_b49530d286d4adf9a5a5ca3eecbb1b5611a1f15c38',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            'http://localhost:8092/simplesaml/module.php/core/welcome',
        ];
        yield 'for-bindings to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/sso',
            '_dcfb5cad9e75a4f54f05896bc454dbca210b085829',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/for-bindings',
            'http://localhost:8092/simplesaml/session.php',
        ];
        yield 'Keycloak\'s broker to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-authnrequest-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
            'ID_3894a772-c6e9-416a-ad76-846f38c871e7',
            self::KEYCLOAK . 'sp/broker/bindings/endpoint',
            '-EyR6_MhiYlEDqynO29Wij-_WW7CjnpUloGSVEFjVnI.kyrCguQFzP4.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'for-bindings to this package, a ReturnTo of 105 bytes, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt',
            self::OCTOBER_1_LONG_RETURN_TO,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/sso',
            '_118cf0716e0bd05824bf5b174d045953333cd2504c',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/for-bindings',
            'http://localhost:8092/simplesaml/session.php?return-to-return-to-return-to-return-to-return-to-return-to-',
        ];
        yield 'Keycloak\'s broker to this package, a client whose internal ID is not a UUID, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-authnrequest-to-bindings-long-relaystate-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
            'ID_f023bf10-c1f3-4217-a0ab-6febc02aac85',
            self::KEYCLOAK . 'sp/broker/bindings/endpoint',
            'FxVRi7Piwr1RNqcv7MoiqBwdwZk9AjwuFDkd8HQ5BMg.6aPnW3NLLrQ.YS1jbGllbnQtb2YtcmVhbG0tc3Atd2hvc2UtaW50ZXJuYWwtaWQtaXMtbm8tdXVpZA',
        ];
    }

    /**
     * Section 9.4, B-5, SAML Profiles §4.1.2: the AuthnRequest of Keycloak's broker as its importer configures it from
     * an identity provider metadata listing HTTP-Redirect alone, asking for its response over HTTP-Redirect: its
     * signature verified by the binding, then refused by the model, which answers over HTTP-POST only (model.md section
     * 8; finding K-2 of tests/Interop/keycloak/README.md). The producer is configured so, the rule stands.
     */
    #[Test]
    public function itRefusesTheAuthnRequestOfKeycloaksBrokerAskingForItsResponseOverHttpRedirect(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(
            self::fixture('real/keycloak-26.7.4-sp-authnrequest-to-bindings-redirect-binding-refused-query-2026-10-01.txt'),
        );

        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('The ProtocolBinding of an AuthnRequest is not HTTP-POST, the one binding the package answers over (section 8).');

        // When
        $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1)),
            self::serviceProvider(
                'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
                self::KEYCLOAK_OCTOBER_1,
            ),
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'sso',
        );
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, M-3: the AuthnRequest of Keycloak's broker under its defaults, to realm idp,
     * unsigned and from a metadata that publishes no key, while realm idp's metadata wants its requests signed: read by
     * the receiver and refused by the model's validate() (saml2-model's finding 2), as Keycloak's own realm idp accepts
     * it only because its client is told not to require a signature (realms/idp.json).
     */
    #[Test]
    public function itRefusesTheUnsignedAuthnRequestOfKeycloaksBrokerUnderItsDefaults(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest(
            self::fixture('real/keycloak-26.7.4-sp-authnrequest-unsigned-refused-query-2026-10-01.txt'),
        );

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1)),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::keycloakIdentityProvider(),
            self::KEYCLOAK . 'idp/protocol/saml',
        );
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.1: the LogoutRequest of Keycloak's broker under its
     * defaults, unsigned over HTTP-Redirect: read by the receiver and refused by the model's validate().
     */
    #[Test]
    public function itRefusesTheUnsignedLogoutRequestOfKeycloaksBrokerUnderItsDefaults(): void
    {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(
            self::fixture('real/keycloak-26.7.4-sp-logoutrequest-unsigned-refused-query-2026-10-01.txt'),
        );
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing key to verify the message with (M-3).');

        // When
        $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), self::clock(self::KEYCLOAK_OCTOBER_1)),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::keycloakIdentityProvider(),
            self::KEYCLOAK . 'idp/protocol/saml',
        );
    }

    /**
     * Section 9.4, section 6.1, B-2, B-5, SAML Profiles §4.4.4.1: a signed LogoutRequest of a real service provider,
     * verified under the key of its metadata, accepted by the binding's authentication, naming the NameID and the
     * session its identity provider issued.
     *
     * @param list<string> $sessionIndexes
     */
    #[Test]
    #[DataProvider('provideLogoutRequests')]
    public function itVerifiesAndValidatesTheSignedLogoutRequestsOfRealServiceProviders(
        string $query,
        string $capturedAt,
        string $serviceProvider,
        IdentityProvider $self,
        string $receivedAt,
        string $id,
        NameIdFormat $format,
        string $nameId,
        array $sessionIndexes,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        // When
        $accepted = $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), self::clock($capturedAt)),
            self::serviceProvider($serviceProvider, $capturedAt),
            $self,
            $receivedAt,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, $format, $nameId, $sessionIndexes],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->nameId->format,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, string, IdentityProvider, string, string, NameIdFormat, string, list<string>}>
     */
    public static function provideLogoutRequests(): iterable
    {
        yield 'for-model to saml2-model, 30 September 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt',
            self::SEPTEMBER_30,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml',
            self::modelIdentityProvider(),
            self::MODEL . 'idp/slo',
            '_b00d8f15bcc6e09626c3d388ce705bb778563bbf5e',
            NameIdFormat::Transient,
            '_a849fe5baadb7fb8e8c621c19269ce4f976adf46',
            ['_0b87387ced75ba1b87f2080d912ff64d06a11e49'],
        ];
        yield 'default-sp to its own identity provider, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml',
            self::simpleSamlPhpIdentityProvider(),
            self::IDP . 'singleLogout',
            '_464dfd53054123a49d09b10f32d28e15f7a3d3129b',
            NameIdFormat::Transient,
            '_fc87e38d42e753e675e72c83982c6b6d1e229f2d1f',
            ['_5b9957dce292a2455b0175462282c36f8023e69017'],
        ];
        yield 'for-bindings to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            'real/simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
            self::bindingsIdentityProvider(),
            self::BINDINGS . 'idp/slo',
            '_8355a005c7bfe4c0fd6d6b4f3f1ba61ed3c162d72a',
            NameIdFormat::Transient,
            '_8105b711c8b244b656186bf9d3410a30b97eb637',
            ['_5adee982b213afbeb74182ac727154288e401622'],
        ];
        yield 'Keycloak\'s broker to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-sp-logoutrequest-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            'real/keycloak-26.7.4-sp-metadata-for-bindings-2026-10-01.xml',
            self::keycloakBindingsIdentityProvider(),
            self::KEYCLOAK_BINDINGS_IDP . 'slo',
            'ID_82970d1a-6f49-4556-a264-67b44245ad10',
            NameIdFormat::Persistent,
            'bindings-alice',
            ['_db380a1883610f4bb2e4a2be420aceeaeb2040e4'],
        ];
    }

    /**
     * Section 9.4, section 6.2, B-5, B-8, SAML Bindings §3.5.4: the response a real identity provider posts, the body a
     * browser posts from the fields of its form, parsed as PHP parses it, read by PostReceiver and validated by the
     * model, its RelayState echoed: SimpleSAMLphp's, its response and its assertion signed (saml20.sign.response, its
     * default), a transient NameID; Keycloak's realm idp's, the response signed and not the assertion (its default), a
     * persistent NameID, as the request asked.
     */
    #[Test]
    #[DataProvider('provideResponseForms')]
    public function itReadsAndValidatesTheResponseFormsOfRealIdentityProviders(
        string $form,
        string $capturedAt,
        IdentityProvider $identityProvider,
        string $requestId,
        string $assertionConsumerService,
        string $audience,
        SignatureCoverage $coverage,
        string $id,
        NameIdFormat $format,
        string $relayState,
    ): void {
        // Given
        $received = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed(self::fixture($form)));

        // When
        $accepted = $received->validate(
            new ResponseValidator(SamlLoader::create(), self::clock($capturedAt), new InMemoryReplayGuard()),
            $identityProvider,
            ExpectedResponse::toRequest($requestId, $assertionConsumerService, $audience),
        );

        // Then
        static::assertSame(
            [$coverage, $id, $format, $relayState],
            [$accepted->coverage, $accepted->responseId, $accepted->assertion->nameId->format, $received->relayState],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, string, string, string, SignatureCoverage, string, NameIdFormat, string}>
     */
    public static function provideResponseForms(): iterable
    {
        yield 'SimpleSAMLphp to default-sp, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-response-form-2026-10-01.txt',
            self::OCTOBER_1_LOGIN,
            self::simpleSamlPhpIdentityProvider(),
            '_b49530d286d4adf9a5a5ca3eecbb1b5611a1f15c38',
            'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
            self::SP . 'metadata/default-sp',
            SignatureCoverage::AssertionAndResponse,
            '_218f31d51ad2954c49b68552d374ce4c9b4e5461cf',
            NameIdFormat::Transient,
            'http://localhost:8092/simplesaml/module.php/core/welcome',
        ];
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            '_41f764b4e7b601cffe0491118060eff82e63b868',
            self::BINDINGS . 'sp/acs',
            self::BINDINGS . 'sp',
            SignatureCoverage::AssertionAndResponse,
            '_f66f960182efa8c5bb823cfa34f88dc9ea47ec92dd',
            NameIdFormat::Transient,
            'bindings login ~',
        ];
        yield 'Keycloak\'s realm idp to its broker, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-response-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            'ID_ce99b63e-1c8f-4f66-bd2c-0c8fad6a8373',
            self::KEYCLOAK . 'sp/broker/idp/endpoint',
            self::KEYCLOAK . 'sp',
            SignatureCoverage::Response,
            'ID_12ee9a72-81c9-4f80-b471-a99fad65cd25',
            NameIdFormat::Persistent,
            'Y0qjsxZND40tqPcUrW6tTFVyZi6CzBonRx1z8ODFegc.nPbFjF3Rt-I.QtJCtf5lQ8yUPwrjYyuKVw',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-response-to-bindings-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            '_31f21e2eeeb8580b3de7068efc6f6a25d74c4e03',
            self::KEYCLOAK_BINDINGS_SP . 'acs',
            self::KEYCLOAK_BINDINGS_SP . 'metadata',
            SignatureCoverage::Response,
            'ID_f3af97bf-4466-4106-8f81-0128f0440904',
            NameIdFormat::Persistent,
            'bindings login ~',
        ];
    }

    /**
     * Section 9.4, section 6.1, B-2, B-5, B-8, SAML Profiles §4.4.4.1: the LogoutResponse a real identity provider signs
     * over HTTP-Redirect, verified as it arrived, its RelayState returned as decoded, what this package sent:
     * SimpleSAMLphp's under sign.logout, its RelayState escaped by PHP's urlencode(), "+" for a space and "%7E" for "~";
     * Keycloak's realm idp's once its client's "Force POST binding" is off, a space written "+" and "~" left as it is.
     */
    #[Test]
    #[DataProvider('provideSignedLogoutResponseQueries')]
    public function itVerifiesAndValidatesTheSignedLogoutResponsesOverHttpRedirect(
        string $query,
        string $capturedAt,
        IdentityProvider $identityProvider,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
        string $id,
        string $relayState,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // When
        $accepted = $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock($capturedAt)),
            $identityProvider,
            $self,
            $receivedAt,
            $requestId,
        );

        // Then
        static::assertSame(
            [Authentication::Binding, $id, StatusCode::Success, $relayState],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->status->code,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, ServiceProvider, string, string, string, string}>
     */
    public static function provideSignedLogoutResponseQueries(): iterable
    {
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            self::bindingsServiceProvider('sp', Binding::HttpRedirect),
            self::BINDINGS . 'sp/slo',
            '_2942fa04f07f16fa845c285b220600bf83b130c3',
            '_10f52db37594bc20921006c87338d15333d7b87d26',
            'bindings logout ~',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-to-bindings-query-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::keycloakBindingsServiceProvider(),
            self::KEYCLOAK_BINDINGS_SP . 'slo',
            '_8b76e5ac5b17b3f1345511b7e6fe4e1d3f927d50',
            'ID_cb3648a6-cb68-4f7e-9884-c136607e40e8',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
    }

    /**
     * Section 9.4, section 6.2, B-5, SAML Bindings §3.5.4, SAML Profiles §4.4.4.2: the LogoutResponse a real identity
     * provider posts, signed in its XML, read by PostReceiver from the body a browser posts, its RelayState echoed:
     * SimpleSAMLphp's to a single logout service published for HTTP-POST alone, under sign.logout; Keycloak's realm
     * idp's under its client's "Force POST binding", its default.
     */
    #[Test]
    #[DataProvider('provideLogoutResponseForms')]
    public function itReadsAndValidatesTheLogoutResponseFormsOfRealIdentityProviders(
        string $form,
        string $capturedAt,
        IdentityProvider $identityProvider,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
        string $id,
        string $relayState,
    ): void {
        // Given
        $received = new PostReceiver(SamlLoader::create())->logoutMessage(BrowserForm::parsed(self::fixture($form)));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // When
        $accepted = $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock($capturedAt)),
            $identityProvider,
            $self,
            $receivedAt,
            $requestId,
        );

        // Then
        static::assertSame(
            [Authentication::XmlSignature, $id, StatusCode::Success, $relayState],
            [
                $accepted->authentication,
                $accepted->response->id,
                $accepted->response->status->code,
                $received->relayState,
            ],
        );
    }

    /**
     * @return iterable<string, array{string, string, IdentityProvider, ServiceProvider, string, string, string, string}>
     */
    public static function provideLogoutResponseForms(): iterable
    {
        yield 'SimpleSAMLphp to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-form-2026-10-01.txt',
            self::OCTOBER_1,
            self::simpleSamlPhpIdentityProvider(),
            self::bindingsServiceProvider('sp-post', Binding::HttpPost),
            self::BINDINGS . 'sp-post/slo',
            '_403fc2f8b14e2523234555dee6caac2a86dfd0c5',
            '_0b010c354af6627fdaa9649efde479bf3809b86ba2',
            str_pad('bindings ~ 80 bytes ', 80, '0123456789'),
        ];
        yield 'Keycloak\'s realm idp to its broker, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::serviceProvider('real/keycloak-26.7.4-sp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1),
            self::KEYCLOAK . 'sp/broker/idp/endpoint',
            'ID_30e99fe4-086c-4dc5-9e6c-02fb852eef5e',
            'ID_dc33ee08-cb71-4b1f-b627-e04427391e5a',
            'kpJCQUGfDkl7xb1GREeOsPVl',
        ];
        yield 'Keycloak\'s realm idp to this package, 1 October 2026' => [
            'real/keycloak-26.7.4-idp-logoutresponse-to-bindings-form-2026-10-01.txt',
            self::KEYCLOAK_OCTOBER_1,
            self::keycloakIdentityProvider(),
            self::keycloakBindingsServiceProvider(),
            self::KEYCLOAK_BINDINGS_SP . 'slo',
            '_baa46cc0aa2b17f87c32107fb5b5dd0e89cf0c9a',
            'ID_e0a3bae3-bb0c-43fd-9bb1-3ad3b090d922',
            'bindings logout ~',
        ];
    }

    /**
     * Section 9.4, §9.2 row 20, B-5, M-2, SAML Profiles §4.4.4.2: the LogoutResponse SimpleSAMLphp's identity provider
     * sends over HTTP-Redirect under its defaults, neither its query string nor its XML signed, read by the receiver
     * and refused by the model's validate() (saml2-model's finding F-1): the producer is wrong, the rule stands.
     */
    #[Test]
    #[DataProvider('provideUnsignedLogoutResponses')]
    public function itRefusesTheUnsignedLogoutResponsesOfSimpleSamlPhp(
        string $query,
        ServiceProvider $self,
        string $receivedAt,
        string $requestId,
    ): void {
        // Given
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage(self::fixture($query));
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new LogicException('A SAMLResponse is received as a LogoutResponse.');
        }

        // Then
        $this->expectException(SignatureRequired::class);
        $this->expectExceptionMessageIs('The message carries no ds:Signature, which the profile requires (M-2).');

        // When
        $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), self::clock(self::OCTOBER_1)),
            self::simpleSamlPhpIdentityProvider(),
            $self,
            $receivedAt,
            $requestId,
        );
    }

    /**
     * @return iterable<string, array{string, ServiceProvider, string, string}>
     */
    public static function provideUnsignedLogoutResponses(): iterable
    {
        yield 'to default-sp, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-unsigned-refused-query-2026-10-01.txt',
            self::serviceProvider('real/simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml', self::OCTOBER_1),
            self::SP . 'saml2-logout.php/default-sp',
            '_464dfd53054123a49d09b10f32d28e15f7a3d3129b',
        ];
        yield 'to this package, 1 October 2026' => [
            'real/simplesamlphp-2.5.3.1-idp-logoutresponse-to-bindings-unsigned-refused-query-2026-10-01.txt',
            self::bindingsServiceProvider('sp-defaults', Binding::HttpRedirect),
            self::BINDINGS . 'sp-defaults/slo',
            '_6a1897a87e69ff532142fe5eb169d633fcfa7362',
        ];
    }

    private static function clock(string $capturedAt): FrozenClock
    {
        return new FrozenClock(new DateTimeImmutable($capturedAt));
    }

    /**
     * Metadata as SimpleSAMLphp served it, read by readTrusted() with a clock at the capture.
     */
    private static function metadata(string $fixture, string $capturedAt): EntityDescriptor
    {
        return new MetadataReader(SamlLoader::create(), self::clock($capturedAt))->readTrusted(
            SamlLoader::create()->load(self::fixture($fixture)),
        );
    }

    /**
     * A service provider of SimpleSAMLphp, its metadata as served.
     */
    private static function serviceProvider(string $fixture, string $capturedAt): ServiceProvider
    {
        $descriptor = self::metadata($fixture, $capturedAt);

        return $descriptor->serviceProvider ?? throw new LogicException('The metadata holds a service provider.');
    }

    /**
     * SimpleSAMLphp's identity provider, its metadata as served on 1 October 2026: HTTP-Redirect alone for its single
     * sign-on and single logout services, its default publication.
     */
    private static function simpleSamlPhpIdentityProvider(): IdentityProvider
    {
        $descriptor = self::metadata('real/simplesamlphp-2.5.3.1-idp-metadata-2026-10-01.xml', self::OCTOBER_1_LOGIN);

        return $descriptor->identityProvider ?? throw new LogicException('The metadata holds an identity provider.');
    }

    /**
     * Keycloak's realm idp, its metadata as served on 1 October 2026, its key generated at the start of the run.
     */
    private static function keycloakIdentityProvider(): IdentityProvider
    {
        $descriptor = self::metadata('real/keycloak-26.7.4-idp-metadata-2026-10-01.xml', self::KEYCLOAK_OCTOBER_1);

        return $descriptor->identityProvider ?? throw new LogicException('The metadata holds an identity provider.');
    }

    /**
     * This package's identity provider as Keycloak's exchange wrote its metadata for the broker's importer: the "idp"
     * test key, HTTP-Redirect alone for its single sign-on and single logout services, wanting its requests signed.
     */
    private static function keycloakBindingsIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::KEYCLOAK_BINDINGS_IDP . 'metadata',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_IDP . 'sso')],
            [new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_IDP . 'slo')],
            [NameIdFormat::Persistent],
            true,
        );
    }

    /**
     * This package's service provider as Keycloak's exchange wrote its metadata for realm idp's converter: the "sp"
     * test key, its assertion consumer service over HTTP-POST, its single logout service over HTTP-Redirect and
     * HTTP-POST, signing its requests and not asking for signed assertions.
     */
    private static function keycloakBindingsServiceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            self::KEYCLOAK_BINDINGS_SP . 'metadata',
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::KEYCLOAK_BINDINGS_SP . 'acs', 0, true)]),
            [
                new Endpoint(Binding::HttpRedirect, self::KEYCLOAK_BINDINGS_SP . 'slo'),
                new Endpoint(Binding::HttpPost, self::KEYCLOAK_BINDINGS_SP . 'slo'),
            ],
            [NameIdFormat::Persistent],
            true,
            false,
        );
    }

    /**
     * The model's identity provider as saml2-model's exchange published it (its
     * tests/Unit/Interop/SimpleSamlPhpDocumentsTest.php).
     */
    private static function modelIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::MODEL . 'idp',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/sso')],
            [new Endpoint(Binding::HttpRedirect, self::MODEL . 'idp/slo')],
            [NameIdFormat::Transient],
            true,
        );
    }

    /**
     * This package's identity provider as the judge's exchange wrote its metadata: the "idp" test key, HTTP-Redirect
     * for its single sign-on and single logout services, wanting its requests signed.
     */
    private static function bindingsIdentityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            self::BINDINGS . 'idp',
            [TestKeys::certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, self::BINDINGS . 'idp/sso')],
            [new Endpoint(Binding::HttpRedirect, self::BINDINGS . 'idp/slo')],
            [NameIdFormat::Transient],
            true,
        );
    }

    /**
     * A service provider of this package as the judge's exchange wrote its metadata: the "sp" test key, its assertion
     * consumer service over HTTP-POST, its single logout service over $logout.
     */
    private static function bindingsServiceProvider(string $name, Binding $logout): ServiceProvider
    {
        return new ServiceProvider(
            self::BINDINGS . $name,
            [TestKeys::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::BINDINGS . $name . '/acs', 0, true)]),
            [new Endpoint($logout, self::BINDINGS . $name . '/slo')],
            [NameIdFormat::Transient],
            true,
            true,
        );
    }
}
