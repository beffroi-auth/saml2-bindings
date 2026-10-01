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
 * The detached signature of a query string received over HTTP-Redirect (section 6.1 steps 5, 7 and 12): the algorithm
 * SigAlg named, read on the closed list of D-5 (B-3); the signature, decoded; the octets of B-2 it covers; and the
 * consumer's Loader, which the Verifier is given (dsig.md §6.4). Nothing is verified when it is built, since the keys
 * are the issuer's and the issuer is in the message: the received message verifies it when the consumer, having chosen
 * the peer with the unverified Issuer, validates it (B-4, B-5).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class DetachedSignature
{
    /**
     * @param SignatureAlgorithm $algorithm the algorithm SigAlg names, one of the closed list (B-3)
     * @param string             $signature the value of Signature, decoded
     * @param SignedOctets       $octets    what the signature covers (B-2)
     * @param Loader             $loader    the consumer's, SamlLoader::create(), which the Verifier is given
     */
    public function __construct(
        public SignatureAlgorithm $algorithm,
        public string $signature,
        public SignedOctets $octets,
        private Loader $loader,
    ) {
    }

    /**
     * The key of the peer's metadata under which the signature is one of the octets (B-4, section 6.1 step 12):
     * Verifier::verifyDetached(), which checks that this build has the algorithm and that the signature is between 256
     * and 1 024 bytes before any key, then tries every key of the role (D-7).
     *
     * @param ?VerificationKeys $keys the keys of the peer's role, verificationKeys() of its metadata, null when it
     *                                holds no signing certificate
     *
     * @throws NoVerificationKey when $keys is null (B-4)
     * @throws AlgorithmUnavailable a PSS algorithm on a build that cannot verify it
     * @throws LimitExceeded when the signature is not between 256 and 1 024 bytes (D-14)
     * @throws SignatureMismatch when no key of the peer verifies it
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
