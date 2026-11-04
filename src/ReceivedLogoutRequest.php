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

final readonly class ReceivedLogoutRequest
{
    public UnverifiedLogoutRequest $request;

    public ?string $relayState;

    public Binding $binding;

    /**
     * @throws InvalidArgumentException
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
     * Section 6.1 step 12
     *
     * @param string $receivedAt the URL of our SingleLogoutService the request arrived at, from our configuration
     *
     * @throws NoVerificationKey
     * @throws MessageRefused
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
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
