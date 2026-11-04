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

final readonly class ReceivedLogoutResponse
{
    public UnverifiedLogoutResponse $response;

    public ?string $relayState;

    public Binding $binding;

    /**
     * @throws InvalidArgumentException
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
     * Section 6.1 step 12
     *
     * @param string $receivedAt the URL of our SingleLogoutService the response arrived at, from our configuration
     *
     * @throws NoVerificationKey
     * @throws MessageRefused
     * @throws RefusedXml
     * @throws InvalidArgumentException when $self is not the role that faces $peer's
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
