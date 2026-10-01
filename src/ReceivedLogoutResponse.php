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
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * A samlp:LogoutResponse received at a single logout service, by either role (section 5.2): the model's unverified
 * response, whose Issuer chooses the peer and whose InResponseTo names the request it answers (M-1), the RelayState,
 * returned and never given to the model (B-9), the binding that carried it, and, over HTTP-Redirect when the query
 * string is signed, its detached signature, which no public property exposes. validate() authenticates the response
 * as the binding says, then validates it through the model.
 */
final readonly class ReceivedLogoutResponse
{
    /**
     * The model's unverified response, whose Issuer chooses the peer and InResponseTo the request (M-1).
     */
    public UnverifiedLogoutResponse $response;

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
     * @throws InvalidArgumentException when $reception holds another message than a LogoutResponse, a programming error
     */
    public function __construct(
        private Reception $reception,
    ) {
        if (! $reception->message instanceof UnverifiedLogoutResponse) {
            throw new InvalidArgumentException('A ReceivedLogoutResponse is built from the reception of a LogoutResponse (section 5.2).');
        }
        $this->response = $reception->message;
        $this->relayState = $reception->relayState;
        $this->binding = $reception->binding;
    }

    /**
     * Section 6.1 step 12. Over HTTP-Redirect with a Signature: the detached signature verified under
     * $peer->verificationKeys() (B-4), then $validator->validateAuthenticatedByBinding(), whose result says
     * Authentication::Binding (B-5). Without a Signature, and over HTTP-POST: $validator->validate(), which refuses an
     * unsigned query string (SignatureRequired, M-2: SAML Profiles §4.4.4.2 requires a logout response signed).
     *
     * @param IdentityProvider|ServiceProvider $peer       the role the consumer chose with the unverified Issuer
     * @param IdentityProvider|ServiceProvider $self       our role, the one that faces $peer's
     * @param string                           $receivedAt the URL of our SingleLogoutService at which the response
     *                                                     arrived, from our configuration (section 6.8)
     * @param string                           $requestId  the ID of the LogoutRequest the response answers (M-10)
     *
     * @throws NoVerificationKey        when the response is signed and $peer holds no signing certificate (B-4)
     * @throws MessageRefused           one of its subclasses, as the model refuses
     * @throws RefusedXml               Dsig's SignatureMismatch, LimitExceeded and AlgorithmUnavailable, and what Core
     *                                  and the model refuse, as they refuse it
     * @throws InvalidArgumentException when $self is not the role that faces $peer's, a programming error of the caller
     */
    public function validate(
        LogoutResponseValidator $validator,
        IdentityProvider|ServiceProvider $peer,
        IdentityProvider|ServiceProvider $self,
        string $receivedAt,
        string $requestId,
    ): AcceptedLogoutResponse {
        $signature = $this->reception->signature;
        if (! $signature instanceof DetachedSignature) {
            return $validator->validate($this->response, $peer, $self, $receivedAt, $requestId);
        }
        $signature->verify($peer->verificationKeys());

        return $validator->validateAuthenticatedByBinding($this->response, $peer, $self, $receivedAt, $requestId);
    }
}
