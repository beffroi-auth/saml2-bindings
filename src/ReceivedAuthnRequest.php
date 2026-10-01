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
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

/**
 * A samlp:AuthnRequest received at a single sign-on service (section 5.2): the model's unverified request, whose
 * Issuer chooses the service provider (M-1), the RelayState, returned and never given to the model (B-9), the binding
 * that carried it, and, over HTTP-Redirect when the query string is signed, its detached signature, which no public
 * property exposes. validate() authenticates the request as the binding says, then validates it through the model, so
 * that the consumer's code is one path whatever the binding.
 */
final readonly class ReceivedAuthnRequest
{
    /**
     * The model's unverified request, whose Issuer chooses the service provider (M-1).
     */
    public UnverifiedAuthnRequest $request;

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
     * @throws InvalidArgumentException when $reception holds another message than an AuthnRequest, a programming error
     */
    public function __construct(
        private Reception $reception,
    ) {
        if (! $reception->message instanceof UnverifiedAuthnRequest) {
            throw new InvalidArgumentException('A ReceivedAuthnRequest is built from the reception of an AuthnRequest (section 5.2).');
        }
        $this->request = $reception->message;
        $this->relayState = $reception->relayState;
        $this->binding = $reception->binding;
    }

    /**
     * Section 6.1 step 12. Over HTTP-Redirect with a Signature: the detached signature verified under
     * $sp->verificationKeys() (B-4), then $validator->validateAuthenticatedByBinding(), whose result says
     * Authentication::Binding (B-5). Without a Signature, and over HTTP-POST: $validator->validate(), which refuses a
     * request either party's metadata wants signed (M-2).
     *
     * @param ServiceProvider  $sp         the service provider the consumer chose with the unverified Issuer
     * @param IdentityProvider $self       our own role
     * @param string           $receivedAt the URL of our SingleSignOnService at which the request arrived, from our
     *                                     configuration (section 6.8)
     *
     * @throws NoVerificationKey when the request is signed and $sp holds no signing certificate (B-4)
     * @throws MessageRefused    one of its subclasses, as the model refuses
     * @throws RefusedXml        Dsig's SignatureMismatch, LimitExceeded and AlgorithmUnavailable, and what Core and the
     *                           model refuse, as they refuse it
     */
    public function validate(
        AuthnRequestValidator $validator,
        ServiceProvider $sp,
        IdentityProvider $self,
        string $receivedAt,
    ): AcceptedAuthnRequest {
        $signature = $this->reception->signature;
        if (! $signature instanceof DetachedSignature) {
            return $validator->validate($this->request, $sp, $self, $receivedAt);
        }
        $signature->verify($sp->verificationKeys());

        return $validator->validateAuthenticatedByBinding($this->request, $sp, $self, $receivedAt);
    }
}
