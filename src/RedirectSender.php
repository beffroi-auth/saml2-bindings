<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Bindings\Internal\Deflater;
use Beffroi\Saml2\Bindings\Internal\DestinationScheme;
use Beffroi\Saml2\Bindings\Internal\Percent;
use Beffroi\Saml2\Bindings\Internal\QueryParameters;
use Beffroi\Saml2\Bindings\Internal\SignedOctets;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Serializer;
use function explode;
use InvalidArgumentException;
use SensitiveParameter;
use function sprintf;
use function str_contains;
use function strlen;
use function strpos;
use function substr;

/**
 * Section 6.3, B-6
 *
 * The arguments are checked first, so that the signing key is never called for a URL the sender then refuses.
 */
final readonly class RedirectSender
{
    /**
     * B-9: a named exception to the 80 bytes of SAML Bindings §3.4.3 and §3.5.3.
     */
    private const int MAX_RELAY_STATE_BYTES = 1_024;

    public function __construct(
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * @param ?Signing $signing    null only when neither party's metadata wants the request signed
     * @param ?string  $relayState at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9, or a Destination that is not an http or https
     *                                  URL, holds a fragment, or holds a query the receiver would refuse
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function authnRequest(
        AuthnRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
        ?string $relayState = null,
    ): string {
        $destination =
            $request->destination ?? throw new InvalidArgumentException('The AuthnRequest holds no Destination, the URL it is sent to (section 6.3).');
        $ownQuery = $this->arguments($relayState, $destination);

        return $this->url(
            new AuthnRequestWriter()->write($request, null),
            'SAMLRequest',
            $destination,
            $ownQuery,
            $relayState,
            $signing,
        );
    }

    /**
     * @param ?string $relayState at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9, or a Destination that is not an http or https
     *                                  URL, holds a fragment, or holds a query the receiver would refuse
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function logoutRequest(
        LogoutRequest $request,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): string {
        $ownQuery = $this->arguments($relayState, $request->destination);

        return $this->url(
            new LogoutRequestWriter()->write($request, null),
            'SAMLRequest',
            $request->destination,
            $ownQuery,
            $relayState,
            $signing,
        );
    }

    /**
     * @param ?string $relayState at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9, or a Destination that is not an http or https
     *                                  URL, holds a fragment, or holds a query the receiver would refuse
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function logoutResponse(
        LogoutResponse $response,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): string {
        $ownQuery = $this->arguments($relayState, $response->destination);

        return $this->url(
            new LogoutResponseWriter()->write($response, null),
            'SAMLResponse',
            $response->destination,
            $ownQuery,
            $relayState,
            $signing,
        );
    }

    /**
     * Section 6.3 step 1
     *
     * @return ?string the query the Destination already holds, without its "?"
     *
     * @throws InvalidArgumentException
     */
    private function arguments(?string $relayState, string $destination): ?string
    {
        $this->checkRelayState($relayState);

        return $this->ownQuery($destination);
    }

    /**
     * @throws InvalidArgumentException
     */
    private function checkRelayState(?string $relayState): void
    {
        if ($relayState === '') {
            throw new InvalidArgumentException('The RelayState is empty (B-9).');
        }
        if ($relayState !== null && strlen($relayState) > self::MAX_RELAY_STATE_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'The RelayState is longer than %d bytes (B-9).',
                self::MAX_RELAY_STATE_BYTES,
            ));
        }
    }

    /**
     * Section 6.3 steps 3 to 6
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     *
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    private function url(
        Document $document,
        string $messageParameter,
        string $destination,
        ?string $ownQuery,
        ?string $relayState,
        #[SensitiveParameter]
        ?Signing $signing,
    ): string {
        $serialized = new Serializer()->serialize($document);
        if (strlen($serialized) > $this->limits->maxInflatedBytes) {
            throw new LimitExceeded(sprintf(
                'The message is longer than maxInflatedBytes, %d bytes, which the receiver refuses once inflated (B-7).',
                $this->limits->maxInflatedBytes,
            ));
        }
        $query = $this->query(
            $messageParameter,
            Percent::encode(Base64::encode(Deflater::deflate($serialized))),
            $relayState === null ? null : Percent::encode($relayState),
            $signing,
        );
        $queryString = $ownQuery === null ? $query : $ownQuery . '&' . $query;
        if (strlen($queryString) > $this->limits->maxQueryStringBytes) {
            throw new LimitExceeded(sprintf(
                'The query string would be longer than maxQueryStringBytes, %d bytes, which the receiver refuses (B-7).',
                $this->limits->maxQueryStringBytes,
            ));
        }

        return $destination . ($ownQuery === null ? '?' : '&') . $query;
    }

    /**
     * Section 6.3 steps 4 and 5
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     *
     * @throws RefusedXml
     */
    private function query(
        string $messageParameter,
        string $message,
        ?string $relayState,
        #[SensitiveParameter]
        ?Signing $signing,
    ): string {
        if (! $signing instanceof Signing) {
            return $messageParameter . '=' . $message . ($relayState === null ? '' : '&RelayState=' . $relayState);
        }
        $octets = new SignedOctets(
            $messageParameter,
            $message,
            $relayState,
            Percent::encode($signing->algorithm->value),
        )->bytes;

        $signature = Percent::encode(Base64::encode($signing->key->sign($octets, $signing->algorithm)));

        return $octets . '&Signature=' . $signature;
    }

    /**
     * Section 6.3 step 1
     *
     * @throws InvalidArgumentException when the Destination is not an http or https URL, holds a fragment, or holds
     *                                  a query the receiver would refuse
     */
    private function ownQuery(string $destination): ?string
    {
        if (! DestinationScheme::isWeb($destination)) {
            throw new InvalidArgumentException('The Destination is neither an http nor an https URL, the only locations a browser is sent to (section 6.3).');
        }
        if (str_contains($destination, '#')) {
            throw new InvalidArgumentException('The Destination holds a fragment, which a URL of HTTP-Redirect does not carry (section 6.3).');
        }
        $start = strpos($destination, '?');
        if ($start === false) {
            return null;
        }
        $query = substr($destination, $start + 1);
        foreach (explode('&', $query) as $segment) {
            try {
                $name = QueryParameters::parameterNamed(explode('=', $segment)[0]);
            } catch (MalformedEncoding $malformed) {
                throw new InvalidArgumentException(
                    'The query of the Destination holds a malformed percent-escape in a name, which the receiver refuses (B-8).',
                    $malformed->getCode(),
                    previous: $malformed,
                );
            }
            if ($name !== null) {
                throw new InvalidArgumentException('The query of the Destination holds a parameter of the binding (B-1).');
            }
        }

        return $query;
    }
}
