<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\Internal\DetachedSignature;
use Beffroi\Saml2\Bindings\Internal\SignedOctets;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * B-4, section 6.1 step 12, dsig.md §6.4: the detached signature verified over its octets by Verifier::verifyDetached()
 * under the keys of the peer's metadata, and refused without them.
 */
final class DetachedSignatureTest extends TestCase
{
    /**
     * B-4, D-7, SAML Bindings §3.4.4.1: the key of the peer under which the signature is one of the octets.
     */
    #[Test]
    public function itReturnsTheKeyThatVerifiesTheOctets(): void
    {
        // Given
        $octets = $this->octets();
        $key = VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'));
        $signature = $this->signature($octets, TestKeys::signingKey('sp')->sign(
            $octets->bytes,
            SignatureAlgorithm::RsaSha256,
        ));

        // When
        $verified = $signature->verify(new VerificationKeys([$key]));

        // Then
        static::assertSame($key, $verified);
    }

    /**
     * §9.3 row 8, B-4, D-7, SAML Metadata §2.4.1.1: every key of the role is tried, the second verifying during a
     * rotation.
     */
    #[Test]
    public function itTriesEveryKeyOfThePeer(): void
    {
        // Given
        $octets = $this->octets();
        $old = VerificationKey::fromCertificateBase64(TestKeys::certificate('idp'));
        $new = VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'));
        $signature = $this->signature($octets, TestKeys::signingKey('sp')->sign(
            $octets->bytes,
            SignatureAlgorithm::RsaSha256,
        ));

        // When
        $verified = $signature->verify(new VerificationKeys([$old, $new]));

        // Then
        static::assertSame($new, $verified);
    }

    /**
     * §9.2 row 18, B-4, B-11, SAML Metadata §2.4.1.1: a peer whose role holds no signing certificate verifies nothing.
     */
    #[Test]
    public function itRefusesAPeerWithoutKey(): void
    {
        // Given
        $octets = $this->octets();
        $signature = $this->signature($octets, TestKeys::signingKey('sp')->sign(
            $octets->bytes,
            SignatureAlgorithm::RsaSha256,
        ));

        // Then
        $this->expectException(NoVerificationKey::class);
        $this->expectExceptionMessageIs('The metadata of the peer holds no signing certificate to verify the query string with (B-4).');

        // When
        $signature->verify(null);
    }

    /**
     * §9.2 row 17, B-4, D-8, SAML Bindings §3.4.4.1: a signature no key of the peer verifies is refused.
     */
    #[Test]
    public function itRefusesASignatureNoKeyOfThePeerVerifies(): void
    {
        // Given
        $octets = $this->octets();
        $signature = $this->signature($octets, TestKeys::signingKey('idp')->sign(
            $octets->bytes,
            SignatureAlgorithm::RsaSha256,
        ));

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $signature->verify(new VerificationKeys([VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'))]));
    }

    /**
     * B-2, SAML Bindings §3.4.4.1: the signature covers the octets and nothing else, the octets of another message
     * among them.
     */
    #[Test]
    public function itRefusesASignatureOfOtherOctets(): void
    {
        // Given
        $other = new SignedOctets(
            'SAMLRequest',
            'b3RoZXI%3D',
            null,
            'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256',
        );
        $signature = $this->signature($this->octets(), TestKeys::signingKey('sp')->sign(
            $other->bytes,
            SignatureAlgorithm::RsaSha256,
        ));

        // Then
        $this->expectException(SignatureMismatch::class);
        $this->expectExceptionMessageIs('No trusted key verifies the detached signature (D-7, D-8).');

        // When
        $signature->verify(new VerificationKeys([VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'))]));
    }

    /**
     * §9.2 row 19, D-14, SAML Bindings §3.4.4.1: a signature shorter than 256 bytes is refused before any key.
     */
    #[Test]
    public function itRefusesASignatureOutsideTheBoundsOfDsig(): void
    {
        // Given
        $signature = $this->signature($this->octets(), str_repeat("\x01", 255));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('A signature is not between 256 and maxSignatureValueBytes, 1024 bytes (D-14).');

        // When
        $signature->verify(new VerificationKeys([VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'))]));
    }

    /**
     * §9.3 row 13, dsig.md §5.1, SAML Bindings §3.4.4.1: RSASSA-PSS on a build without PHP 8.5 and OpenSSL 3.1 is
     * refused before any key.
     */
    #[Test]
    public function itRefusesAnAlgorithmTheBuildLacks(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('This build verifies RSASSA-PSS: PHP 8.5 and OpenSSL 3.1.');
        }
        $octets = $this->octets();
        $signature = new DetachedSignature(
            SignatureAlgorithm::RsaPssSha256,
            TestKeys::signingKey('sp')->sign($octets->bytes, SignatureAlgorithm::RsaSha256),
            $octets,
            SamlLoader::create(),
        );

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot verify RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        $signature->verify(new VerificationKeys([VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'))]));
    }

    private function octets(): SignedOctets
    {
        return new SignedOctets(
            'SAMLRequest',
            'fZDB%2Bq0%3D',
            'state',
            'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256',
        );
    }

    private function signature(SignedOctets $octets, string $signature): DetachedSignature
    {
        return new DetachedSignature(SignatureAlgorithm::RsaSha256, $signature, $octets, SamlLoader::create());
    }
}
