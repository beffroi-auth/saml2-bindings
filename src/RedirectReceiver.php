<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\XmlSignatureRefused;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Bindings\Internal\Inflater;
use Beffroi\Saml2\Bindings\Internal\Percent;
use Beffroi\Saml2\Bindings\Internal\QueryParameters;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use function sprintf;
use function strlen;

/**
 * HTTP-Redirect received, in the order of section 6.1 (section 5.2): the raw query string bounded, its parameters read
 * before anything is decoded (B-1, B-3, B-9), the octets of B-2 kept, then the message decoded from the very value
 * those octets hold, inflated under its bound (B-7, B-8), loaded by the consumer's Loader as it is (B-10), refused when
 * its root holds a ds:Signature (B-6), and read by the model's Unverified*::of() (M-1). Nothing is verified here: the
 * keys are those of the issuer the message names, and the received message verifies its signature when the consumer
 * validates it (B-4, B-5). Which message is expected is the method the consumer calls, which its endpoint decides.
 */
final readonly class RedirectReceiver
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

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
        [$parameters, $document] = $this->receive($queryString, ['SAMLRequest']);

        return new ReceivedAuthnRequest(
            UnverifiedAuthnRequest::of($document),
            $parameters->relayState,
            Binding::HttpRedirect,
            $parameters->signature,
        );
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
        [$parameters, $document] = $this->receive($queryString, ['SAMLRequest', 'SAMLResponse']);

        return match ($parameters->messageParameter) {
            'SAMLRequest' => new ReceivedLogoutRequest(
                UnverifiedLogoutRequest::of($document),
                $parameters->relayState,
                Binding::HttpRedirect,
                $parameters->signature,
            ),
            'SAMLResponse' => new ReceivedLogoutResponse(
                UnverifiedLogoutResponse::of($document),
                $parameters->relayState,
                Binding::HttpRedirect,
                $parameters->signature,
            ),
        };
    }

    /**
     * Section 6.1 steps 1 to 10: the bound, the parameters and the octets (QueryParameters), then the message decoded
     * from the raw value the octets hold, the document loaded, and no XML signature in it.
     *
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters the message parameters the method takes
     *
     * @return array{QueryParameters, Document}
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    private function receive(string $queryString, array $messageParameters): array
    {
        if (strlen($queryString) > $this->limits->maxQueryStringBytes) {
            throw new LimitExceeded(sprintf(
                'The query string is longer than maxQueryStringBytes, %d bytes (B-7).',
                $this->limits->maxQueryStringBytes,
            ));
        }
        $parameters = QueryParameters::read($queryString, $messageParameters, $this->loader);
        $document = $this->loader->load(Inflater::inflate(
            Base64::decode(Percent::decode($parameters->message)),
            $this->limits->maxInflatedBytes,
        ));
        if (Children::optional($document->root(), new Name(self::DSIG, 'Signature')) instanceof Element) {
            throw new XmlSignatureRefused('The message received over HTTP-Redirect holds a ds:Signature, which the binding removes (B-6).');
        }

        return [$parameters, $document];
    }
}
