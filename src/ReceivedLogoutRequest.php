<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\NoVerificationKey;
use Beffroi\Saml2\Bindings\Internal\DetachedSignature;
use Beffroi\Saml2\Bindings\Internal\Reception;
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
     * The model's unverified request, whose Issuer chooses the peer (M-1).
     */
    public UnverifiedLogoutRequest $request;

    /**
     * RelayState, decoded (B-9).
     */
    public ?string $relayState;

    /**
     * HttpRedirect or HttpPost.
     */
    public Binding $binding;

    /**
     * Built by the receivers from one input read whole; outside the compatibility surface of section 5 (section 5.2).
     * The message and the detached signature are both the reception's, so that the octets the signature covers are
     * those of the very input the message was decoded from, whoever builds the object (B-5).
     *
     * @throws InvalidArgumentException when $reception holds another message than a LogoutRequest, a programming error
     */
    public function __construct(
        private Reception $reception,
    ) {
        if (! $reception->message instanceof UnverifiedLogoutRequest) {
            throw new InvalidArgumentException('A ReceivedLogoutRequest is built from the reception of a LogoutRequest (section 5.2).');
        }
        $this->request = $reception->message;
        $this->relayState = $reception->relayState;
        $this->binding = $reception->binding;
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
        $signature = $this->reception->signature;
        if (! $signature instanceof DetachedSignature) {
            return $validator->validate($this->request, $peer, $self, $receivedAt);
        }
        $signature->verify($peer->verificationKeys());

        return $validator->validateAuthenticatedByBinding($this->request, $peer, $self, $receivedAt);
    }
}
