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
 * HTTP-Redirect received, in the order of section 6.1 (section 5.2): the raw query string bounded, its parameters read
 * before anything is decoded (B-1, B-3, B-9), the octets of B-2 kept, then the message decoded from the very value
 * those octets hold, inflated under its bound (B-7, B-8), loaded by the consumer's Loader as it is (B-10), refused when
 * its root holds a ds:Signature (B-6), and read by the model's Unverified*::of() (M-1), all of it by one Reception of
 * the query string, which the received message holds whole (B-5). Nothing is verified here: the keys are those of the
 * issuer the message names, and the received message verifies its signature when the consumer validates it (B-4).
 * Which message is expected is the method the consumer calls, which its endpoint decides.
 */
final readonly class RedirectReceiver
{
    /**
     * @param Loader        $loader SamlLoader::create(), the model's validators' too (M-14)
     * @param BindingLimits $limits maxQueryStringBytes and maxInflatedBytes (section 7)
     */
    public function __construct(
        private Loader $loader,
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * A SAMLRequest carrying a samlp:AuthnRequest, received at a single sign-on service.
     *
     * @param string $queryString the raw query string as it arrived, without its leading "?", never decoded nor
     *                            re-encoded by anyone before (section 6.8)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core, Dsig and the model refuse, as they refuse it
     */
    public function authnRequest(string $queryString): ReceivedAuthnRequest
    {
        return new ReceivedAuthnRequest($this->receive($queryString, Service::SingleSignOn));
    }

    /**
     * A SAMLRequest carrying a samlp:LogoutRequest, or a SAMLResponse carrying a samlp:LogoutResponse, received at a
     * single logout service.
     *
     * @param string $queryString the raw query string as it arrived, without its leading "?", never decoded nor
     *                            re-encoded by anyone before (section 6.8)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core, Dsig and the model refuse, as they refuse it
     */
    public function logoutMessage(string $queryString): ReceivedLogoutRequest|ReceivedLogoutResponse
    {
        $reception = $this->receive($queryString, Service::SingleLogout);

        return $reception->message instanceof UnverifiedLogoutRequest
            ? new ReceivedLogoutRequest($reception)
            : new ReceivedLogoutResponse($reception);
    }

    /**
     * Section 6.1 steps 1 to 11, the query string read whole under the bounds of section 7.
     *
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
