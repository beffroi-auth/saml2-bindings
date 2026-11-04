<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Internal\Reception;
use Beffroi\Saml2\Bindings\Internal\Service;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;

final readonly class RedirectReceiver
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
     * @param string $queryString the raw query string, without its leading "?", never decoded nor re-encoded
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public function authnRequest(string $queryString): ReceivedAuthnRequest
    {
        return new ReceivedAuthnRequest($this->receive($queryString, Service::SingleSignOn));
    }

    /**
     * @param string $queryString the raw query string, without its leading "?", never decoded nor re-encoded
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public function logoutMessage(string $queryString): ReceivedLogoutRequest|ReceivedLogoutResponse
    {
        $reception = $this->receive($queryString, Service::SingleLogout);

        return $reception->message instanceof UnverifiedLogoutRequest
            ? new ReceivedLogoutRequest($reception)
            : new ReceivedLogoutResponse($reception);
    }

    /**
     * @throws BindingRefused
     * @throws RefusedXml
     */
    private function receive(string $queryString, Service $service): Reception
    {
        return Reception::ofQueryString(
            $queryString,
            $service,
            $this->loader,
            $this->limits->maxQueryStringBytes,
            $this->limits->maxInflatedBytes,
        );
    }
}
