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

final readonly class ReceivedAuthnRequest
{
    public UnverifiedAuthnRequest $request;

    public ?string $relayState;

    public Binding $binding;

    /**
     * @throws InvalidArgumentException
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
     * Section 6.1 step 12
     *
     * @param string $receivedAt the URL of our SingleSignOnService the request arrived at, from our configuration
     *
     * @throws NoVerificationKey
     * @throws MessageRefused
     * @throws RefusedXml
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
