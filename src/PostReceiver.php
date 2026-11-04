<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;

final readonly class PostReceiver
{
    /**
     * @param Loader $loader SamlLoader::create(), the one the model's validators take too (M-14)
     */
    public function __construct(
        private Loader $loader,
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * @param array<array-key, mixed> $fields the form body, as the consumer's parser decoded it
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public function response(array $fields): ReceivedResponse
    {
        return new ReceivedResponse($this->receive($fields, Service::AssertionConsumer));
    }

    /**
     * @param array<array-key, mixed> $fields the form body, as the consumer's parser decoded it
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public function authnRequest(array $fields): ReceivedAuthnRequest
    {
        return new ReceivedAuthnRequest($this->receive($fields, Service::SingleSignOn));
    }

    /**
     * @param array<array-key, mixed> $fields the form body, as the consumer's parser decoded it
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public function logoutMessage(array $fields): ReceivedLogoutRequest|ReceivedLogoutResponse
    {
        $reception = $this->receive($fields, Service::SingleLogout);

        return $reception->message instanceof UnverifiedLogoutRequest
            ? new ReceivedLogoutRequest($reception)
            : new ReceivedLogoutResponse($reception);
    }

    /**
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
