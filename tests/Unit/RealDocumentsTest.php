<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Bindings\Tests\Unit\Internal\CodecFixtures;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.4: the query strings SimpleSAMLphp 2.5.3.1 sent over HTTP-Redirect, bytes as received, verified and
 * validated through RedirectReceiver with a clock frozen at their capture. Its service provider for-model, under
 * sign.authnrequest and sign.logout, sent its AuthnRequest and its LogoutRequest to saml2-model's identity provider on
 * 30 September 2026, in the exchange of saml2-model's harness (its tests/Interop/simplesamlphp/README.md, section 4);
 * the query strings and for-model's metadata are copied from saml2-model's tests/Fixture/real/ (tests/Fixture/real/
 * README.md). The identity provider is the model's as the exchange published it: the "idp" test key, HTTP-Redirect for
 * its single sign-on and single logout services, wanting its requests signed.
 */
final class RealDocumentsTest extends TestCase
{
    use CodecFixtures;

    private const string SP = 'http://localhost:8082/simplesaml/module.php/saml/sp/';

    private const string MODEL = 'http://localhost:8083/model/';

    private const string CAPTURED_AT = '2026-09-30T13:07:34Z';

    /**
     * Section 9.4, section 6.1, B-2, B-5, SAML Bindings §3.4.4.1: for-model's signed AuthnRequest, its signature over
     * SAMLRequest, RelayState and SigAlg as they arrived verified under the key of for-model's metadata, accepted by
     * the binding's authentication, its RelayState, the ReturnTo URL of 44 bytes, returned as decoded.
     */
    #[Test]
    public function itVerifiesAndValidatesTheAuthnRequestOfSimpleSamlPhp(): void
    {
        // Given
        $received = $this->receiver()->authnRequest(self::fixture('real/simplesamlphp-2.5.3.1-sp-authnrequest-to-model-query-2026-09-30.txt'));

        // When
        $accepted = $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable(self::CAPTURED_AT))),
            $this->serviceProvider(),
            $this->modelIdentityProvider(),
            self::MODEL . 'idp/sso',
        );

        // Then
        static::assertSame(
            [
                Authentication::Binding,
                '_ef4cb04a9098a02745f19851d7b70d2e7712c1aa4d',
                self::SP . 'saml2-acs.php/for-model',
                'http://localhost:8082/simplesaml/session.php',
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->assertionConsumerService->location,
                $received->relayState,
            ],
        );
    }

    /**
     * Section 9.4, section 6.1, B-2, B-5, SAML Profiles §4.4.4.1: for-model's signed LogoutRequest, verified under the
     * key of for-model's metadata, accepted by the binding's authentication, naming the transient NameID and the
     * session the model issued.
     */
    #[Test]
    public function itVerifiesAndValidatesTheLogoutRequestOfSimpleSamlPhp(): void
    {
        // Given
        $received = $this->receiver()->logoutMessage(self::fixture('real/simplesamlphp-2.5.3.1-sp-logoutrequest-to-model-query-2026-09-30.txt'));
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new LogicException('A SAMLRequest is received as a LogoutRequest.');
        }

        // When
        $accepted = $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), new FrozenClock(new DateTimeImmutable(self::CAPTURED_AT))),
            $this->serviceProvider(),
            $this->modelIdentityProvider(),
            self::MODEL . 'idp/slo',
        );

        // Then
        static::assertSame(
            [
                Authentication::Binding,
                '_b00d8f15bcc6e09626c3d388ce705bb778563bbf5e',
                NameIdFormat::Transient,
                '_a849fe5baadb7fb8e8c621c19269ce4f976adf46',
                ['_0b87387ced75ba1b87f2080d912ff64d06a11e49'],
            ],
            [
                $accepted->authentication,
                $accepted->request->id,
                $accepted->request->nameId->format,
                $accepted->request->nameId->value,
                $accepted->request->sessionIndexes,
            ],
        );
    }

    private function receiver(): RedirectReceiver
    {
        return new RedirectReceiver(SamlLoader::create());
    }

    /**
     * for-model's metadata as it was served, read by readTrusted() with a clock at the capture.
     */
    private function serviceProvider(): ServiceProvider
    {
        $descriptor = new MetadataReader(
            SamlLoader::create(),
            new FrozenClock(new DateTimeImmutable(self::CAPTURED_AT)),
        )->readTrusted(SamlLoader::create()->load(self::fixture('real/simplesamlphp-2.5.3.1-sp-metadata-for-model-2026-09-30.xml')));

        return (
            $descriptor->serviceProvider ?? throw new LogicException('The metadata of for-model holds a service provider.')
        );
    }

    /**
     * The model's identity provider as the exchange published it (saml2-model's
     * tests/Unit/Interop/SimpleSamlPhpDocumentsTest.php).
     */
    private function modelIdentityProvider(): IdentityProvider
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
}
