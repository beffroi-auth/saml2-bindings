<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Bindings\Exception\BindingRefused;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\XmlSignatureRefused;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use function sprintf;
use function strlen;

/**
 * One input a binding received, read whole (section 5.2, B-5): the model's unverified message, the RelayState, the
 * binding, and, over a signed query string, the detached signature of that very input. The message and the octets of
 * its signature come out of one decoding of one input and can never be paired otherwise: the constructor is private,
 * and the factories take the raw input, never a document or a signature, and do the whole reading themselves. The
 * Received* classes take this object and nothing else, so that whoever builds one, the message it validates is the
 * message whose octets its signature covers.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Reception
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @param ?string            $relayState RelayState, decoded (B-9)
     * @param ?DetachedSignature $signature  the detached signature of the same input, or null when it has none
     */
    private function __construct(
        public UnverifiedAuthnRequest|UnverifiedLogoutRequest|UnverifiedLogoutResponse $message,
        public ?string $relayState,
        public Binding $binding,
        public ?DetachedSignature $signature,
    ) {
    }

    /**
     * HTTP-Redirect, section 6.1 steps 1 to 11, in their order: the query string bounded, its parameters and the octets
     * of B-2 read before anything is decoded (QueryParameters), the message decoded from the raw value those octets
     * hold, inflated under its bound (B-7, B-8), loaded by the consumer's Loader as it is (B-10), refused when its root
     * holds a ds:Signature (B-6), and read as the service expects (M-1).
     *
     * @param string  $queryString         the raw query string as it arrived, without its leading "?"
     * @param Service $service             the service the method serves
     * @param Loader  $loader              the consumer's, SamlLoader::create(), the Verifier's too (M-14)
     * @param int     $maxQueryStringBytes the bound of the query string (section 7)
     * @param int     $maxInflatedBytes    the bound of the inflated message (section 7)
     *
     * @throws BindingRefused one of its subclasses, naming the rule (B-11)
     * @throws RefusedXml     what Core, Dsig and the model refuse, as they refuse it
     */
    public static function ofQueryString(
        string $queryString,
        Service $service,
        Loader $loader,
        int $maxQueryStringBytes,
        int $maxInflatedBytes,
    ): self {
        if (strlen($queryString) > $maxQueryStringBytes) {
            throw new LimitExceeded(sprintf(
                'The query string is longer than maxQueryStringBytes, %d bytes (B-7).',
                $maxQueryStringBytes,
            ));
        }
        $parameters = QueryParameters::read($queryString, $service->messageParameters(), $loader);
        $document = $loader->load(Inflater::inflate(
            Base64::decode(Percent::decode($parameters->message)),
            $maxInflatedBytes,
        ));
        if (Children::optional($document->root(), new Name(self::DSIG, 'Signature')) instanceof Element) {
            throw new XmlSignatureRefused('The message received over HTTP-Redirect holds a ds:Signature, which the binding removes (B-6).');
        }

        return new self(
            $service->read($parameters->messageParameter, $document),
            $parameters->relayState,
            Binding::HttpRedirect,
            $parameters->signature,
        );
    }
}
