<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Xml\Core\Exception\RefusedXml;
use InvalidArgumentException;

final readonly class ReceivedResponse
{
    public UnverifiedResponse $response;

    public ?string $relayState;

    public Binding $binding;

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(Reception $reception)
    {
        if (! $reception->message instanceof UnverifiedResponse) {
            throw new InvalidArgumentException('A ReceivedResponse is built from the reception of a Response (section 5.2).');
        }
        $this->response = $reception->message;
        $this->relayState = $reception->relayState;
        $this->binding = $reception->binding;
    }

    /**
     * Section 6.2 step 7
     *
     * @throws MessageRefused UnsuccessfulResponse for a failure
     * @throws RefusedXml
     */
    public function validate(
        ResponseValidator $validator,
        IdentityProvider $idp,
        ExpectedResponse $expected,
    ): AcceptedAssertion {
        return $validator->validate($this->response, $idp, $expected);
    }
}
