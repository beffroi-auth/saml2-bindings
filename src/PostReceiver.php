<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;

/**
 * HTTP-POST received, in the order of section 6.2 (section 5.2): the fields of the form read before anything is
 * decoded (B-1, B-9), the message field bounded (B-7), then decoded as base64, its line breaks removed and any other
 * whitespace refused (B-8), never inflated, loaded by the consumer's Loader as it is (B-10), and read by the model's
 * Unverified*::of() (M-1), all of it by one Reception of the form, which the received message holds whole (B-5).
 * Nothing looks for a ds:Signature: the message carries its XML signatures, which the model verifies when the
 * consumer validates it. Which message is expected is the method the consumer calls, which its endpoint decides.
 */
final readonly class PostReceiver
{
    /**
     * @param Loader        $loader SamlLoader::create(), the model's validators' too (M-14)
     * @param BindingLimits $limits maxFormValueBytes (section 7)
     */
    public function __construct(
        private Loader $loader,
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * A SAMLResponse carrying a samlp:Response, received at an assertion consumer service.
     *
     * @param array<array-key, mixed> $fields the fields of the application/x-www-form-urlencoded body, as the
     *                                        consumer's parser decoded them (section 6.8)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core and the model refuse, as they refuse it
     */
    public function response(array $fields): ReceivedResponse
    {
        return new ReceivedResponse($this->receive($fields, Service::AssertionConsumer));
    }

    /**
     * A SAMLRequest carrying a samlp:AuthnRequest, received at a single sign-on service.
     *
     * @param array<array-key, mixed> $fields the fields of the application/x-www-form-urlencoded body, as the
     *                                        consumer's parser decoded them (section 6.8)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core and the model refuse, as they refuse it
     */
    public function authnRequest(array $fields): ReceivedAuthnRequest
    {
        return new ReceivedAuthnRequest($this->receive($fields, Service::SingleSignOn));
    }

    /**
     * A SAMLRequest carrying a samlp:LogoutRequest, or a SAMLResponse carrying a samlp:LogoutResponse, received at a
     * single logout service.
     *
     * @param array<array-key, mixed> $fields the fields of the application/x-www-form-urlencoded body, as the
     *                                        consumer's parser decoded them (section 6.8)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core and the model refuse, as they refuse it
     */
    public function logoutMessage(array $fields): ReceivedLogoutRequest|ReceivedLogoutResponse
    {
        $reception = $this->receive($fields, Service::SingleLogout);

        return $reception->message instanceof UnverifiedLogoutRequest
            ? new ReceivedLogoutRequest($reception)
            : new ReceivedLogoutResponse($reception);
    }

    /**
     * Section 6.2 steps 1 to 6, the form read whole under the bound of section 7.
     *
     * @param array<array-key, mixed> $fields
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    private function receive(array $fields, Service $service): Reception
    {
        return Reception::ofForm($fields, $service, $this->loader, $this->limits->maxFormValueBytes);
    }
}
