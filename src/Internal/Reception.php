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
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Core\Name;
use Dom\Element;
use InvalidArgumentException;
use function sprintf;
use function strlen;

/**
 * Section 5.2, B-5
 *
 * Built from the raw input only, so that a message can never be paired with another input's signature.
 *
 * @internal
 */
final readonly class Reception
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private function __construct(
        public UnverifiedAuthnRequest|UnverifiedLogoutRequest|UnverifiedLogoutResponse|UnverifiedResponse $message,
        public ?string $relayState,
        public Binding $binding,
        public ?DetachedSignature $signature,
    ) {
    }

    /**
     * Section 6.1 steps 1 to 11
     *
     * @throws BindingRefused
     * @throws RefusedXml
     * @throws InvalidArgumentException for the assertion consumer service (B-12)
     */
    public static function ofQueryString(
        string $queryString,
        Service $service,
        Loader $loader,
        int $maxQueryStringBytes,
        int $maxInflatedBytes,
    ): self {
        if ($service === Service::AssertionConsumer) {
            throw new InvalidArgumentException('A response never travels over HTTP-Redirect (B-12).');
        }
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

    /**
     * Section 6.2 steps 1 to 6
     *
     * Nothing looks for a ds:Signature: over HTTP-POST the message carries its own XML signatures.
     *
     * @param array<array-key, mixed> $fields
     *
     * @throws BindingRefused
     * @throws RefusedXml
     */
    public static function ofForm(array $fields, Service $service, Loader $loader, int $maxFormValueBytes): self
    {
        $read = FormFields::read($fields, $service->messageParameters(), $maxFormValueBytes);
        $document = $loader->load(Base64::decodeWrapped($read->message));

        return new self(
            $service->read($read->messageParameter, $document),
            $read->relayState,
            Binding::HttpPost,
            null,
        );
    }
}
