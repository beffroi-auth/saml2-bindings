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

/**
 * A samlp:Response received at an assertion consumer service, over HTTP-POST only (section 5.2, B-12): the model's
 * unverified response, whose Issuer chooses the identity provider and whose InResponseTo names the request it answers
 * (M-1), the RelayState, returned and never given to the model (B-9), and the binding that carried it. The response
 * carries its XML signatures, and no detached signature travels with it: validate() calls the model's validate(),
 * which verifies them, so that the consumer's code is the one path of every received message.
 */
final readonly class ReceivedResponse
{
    /**
     * The model's unverified response, whose Issuer chooses the identity provider and InResponseTo the request (M-1).
     */
    public UnverifiedResponse $response;

    /**
     * RelayState, as the form carried it (B-9).
     */
    public ?string $relayState;

    /**
     * HttpPost, the one binding a response travels (B-12).
     */
    public Binding $binding;

    /**
     * Built by the receiver from one form read whole; outside the compatibility surface of section 5 (section 5.2).
     *
     * @throws InvalidArgumentException when $reception holds another message than a Response, a programming error
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
     * Section 6.2 step 7: the model's validate(), which verifies the XML signatures of the response and its assertion
     * under $idp's keys (M-2, M-3) and validates them (B-5).
     *
     * @param IdentityProvider $idp      the identity provider the consumer chose with the unverified Issuer
     * @param ExpectedResponse $expected the request the response answers, or none, the URL of our assertion consumer
     *                                   service at which it arrived, from our configuration (section 6.8), and our
     *                                   entity ID
     *
     * @throws MessageRefused one of its subclasses, as the model refuses, UnsuccessfulResponse for a failure
     * @throws RefusedXml     Dsig's refusals, and what Core and the model refuse, as they refuse it
     */
    public function validate(
        ResponseValidator $validator,
        IdentityProvider $idp,
        ExpectedResponse $expected,
    ): AcceptedAssertion {
        return $validator->validate($this->response, $idp, $expected);
    }
}
