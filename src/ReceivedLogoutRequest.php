<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\Internal\DetachedSignature;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutRequest;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * A samlp:LogoutRequest received at a single logout service, by either role (section 5.2): the model's unverified
 * request, whose Issuer chooses the peer (M-1), the RelayState, returned and never given to the model (B-9), the
 * binding that carried it, and, over HTTP-Redirect when the query string is signed, its detached signature, which no
 * public property exposes. validate() authenticates the request as the binding says, then validates it through the
 * model.
 */
final readonly class ReceivedLogoutRequest
{
    /**
     * Built by the receivers; outside the compatibility surface of section 5 (section 5.2). Built by hand, it gains
     * nothing: without a signature it reaches the model's validate(), and with one it needs octets the peer's key
     * signed.
     *
     * @param ?string            $relayState RelayState, decoded (B-9)
     * @param Binding            $binding    HttpRedirect or HttpPost
     * @param ?DetachedSignature $signature  the detached signature of a signed query string over HTTP-Redirect, null
     *                                       otherwise
     */
    public function __construct(
        public UnverifiedLogoutRequest $request,
        public ?string $relayState,
        public Binding $binding,
        private ?DetachedSignature $signature = null,
    ) {
    }

    /**
     * Section 6.1 step 12. Over HTTP-Redirect with a Signature: the detached signature verified under
     * $peer->verificationKeys() (B-4), then $validator->validateAuthenticatedByBinding(), whose result says
     * Authentication::Binding (B-5). Without a Signature, and over HTTP-POST: $validator->validate(), which refuses an
     * unsigned query string (SignatureRequired, M-2: SAML Profiles §4.4.4.1 requires a logout request signed).
     *
     * @param IdentityProvider|ServiceProvider $peer       the role the consumer chose with the unverified Issuer
     * @param IdentityProvider|ServiceProvider $self       our role, the one that faces $peer's
     * @param string                           $receivedAt the URL of our SingleLogoutService at which the request
     *                                                     arrived, from our configuration (section 6.8)
     *
     * @throws NoVerificationKey        when the request is signed and $peer holds no signing certificate (B-4)
     * @throws MessageRefused           one of its subclasses, as the model refuses
     * @throws RefusedXml               Dsig's SignatureMismatch, LimitExceeded and AlgorithmUnavailable, and what Core
     *                                  and the model refuse, as they refuse it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's, a programming error of the caller
     */
    public function validate(
        LogoutRequestValidator $validator,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
    ): AcceptedLogoutRequest {
        if (! $this->signature instanceof DetachedSignature) {
            return $validator->validate($this->request, $peer, $self, $receivedAt);
        }
        $this->signature->verify($peer->verificationKeys());

        return $validator->validateAuthenticatedByBinding($this->request, $peer, $self, $receivedAt);
    }
}
