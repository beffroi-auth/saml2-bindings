<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\Exception\LimitExceeded;
use Beffroi\Xml\Dsig\Exception\SignatureMismatch;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;

/**
 * Nothing is verified when it is built: the keys are the issuer's, and the consumer finds the issuer in the message
 * first (B-4, B-5).
 *
 * @internal
 */
final readonly class DetachedSignature
{
    /**
     * @param string $signature the value of Signature, decoded
     * @param Loader $loader    the consumer's, SamlLoader::create()
     */
    public function __construct(
        public SignatureAlgorithm $algorithm,
        public string $signature,
        public SignedOctets $octets,
        private Loader $loader,
    ) {
    }

    /**
     * B-4, section 6.1 step 12
     *
     * @throws NoVerificationKey
     * @throws AlgorithmUnavailable a PSS algorithm on a build that cannot verify it
     * @throws LimitExceeded when the signature is not between 256 and 1 024 bytes (D-14)
     * @throws SignatureMismatch
     */
    public function verify(?VerificationKeys $keys): VerificationKey
    {
        if (! $keys instanceof VerificationKeys) {
            throw new NoVerificationKey('The metadata of the peer holds no signing certificate to verify the query string with (B-4).');
        }

        return new Verifier($this->loader)->verifyDetached(
            $this->octets->bytes,
            $this->signature,
            $this->algorithm,
            $keys,
        );
    }
}
