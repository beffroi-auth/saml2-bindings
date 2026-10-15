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
 * HTTP-Redirect sent, in the order of section 6.3 (section 5.3): first every check that needs nothing but the
 * arguments, the RelayState (B-9) and the message's Destination, so that the signing key is never called for a URL the
 * sender then refuses; then the message written by the model's writer with no Signing, so that it carries no XML
 * signature (B-6), serialized once by Core's Serializer (B-10) and bounded as the receiver bounds it once inflated
 * (B-7), raw-deflated, base64-encoded on one line and percent-encoded in uppercase hexadecimal (B-8); then, when a
 * Signing is given, the octets of B-2 signed through the Dsig signing port of the Signing, and the URL built on the
 * Destination, its query bounded as the receiver bounds it. What it writes, the package's receiver reads under the same
 * BindingLimits. Only what the profiles let travel: an AuthnRequest, signed or not, and the two logout messages, always
 * signed; no method sends a Response (B-12).
 */
final readonly class RedirectSender
{
    /**
     * B-9: 1 024 bytes once decoded, a named and bounded exception to the 80 bytes of SAML Bindings §3.4.3 and §3.5.3
     * (section 8).
     */
    private const int MAX_RELAY_STATE_BYTES = 1_024;

    /**
     * @param BindingLimits $limits maxInflatedBytes and maxQueryStringBytes, the bounds of the receiver the URL is
     *                              written for (section 7)
     */
    public function __construct(
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * The URL the browser is sent to: the request's Destination, then SAMLRequest, RelayState when given, and SigAlg
     * and Signature when $signing is given, in that order (B-2). The model's writer is called without signing (B-6).
     *
     * @param ?Signing $signing    the service provider's, or null for a request neither party's metadata wants signed
     *                             (section 5.3)
     * @param ?string  $relayState opaque, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination
     *                                  missing, whose scheme is neither http nor https, or holding a fragment or a
     *                                  query the receiver would refuse (section 6.3 step 1), what the writer refuses
     *                                  so
     * @throws LimitExceeded            a serialized message longer than maxInflatedBytes, or a query string longer
     *                                  than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * The same, a LogoutRequest in SAMLRequest, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination whose
     *                                  scheme is neither http nor https, or that holds a fragment or a query the
     *                                  receiver would refuse (section 6.3 step 1), what the writer refuses so
     * @throws LimitExceeded            a serialized message longer than maxInflatedBytes, or a query string longer
     *                                  than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * The same, a LogoutResponse in SAMLResponse, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination whose
     *                                  scheme is neither http nor https, or that holds a fragment or a query the
     *                                  receiver would refuse (section 6.3 step 1)
     * @throws LimitExceeded            a serialized message longer than maxInflatedBytes, or a query string longer
     *                                  than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * Step 1, what needs nothing but the arguments, before anything is written or signed: the RelayState, then the
     * Destination.
     *
     * @return ?string the query the Destination already holds, without its "?", or null when it holds none
     *
     * @throws InvalidArgumentException a programming error of the caller
     */
    private function arguments(?string $relayState, string $destination): ?string
    {
        $this->checkRelayState($relayState);

        return $this->ownQuery($destination);
    }

    /**
     * Step 1: a RelayState, when given, neither empty nor longer than 1 024 bytes (B-9).
     *
     * @throws InvalidArgumentException a programming error of the caller
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
     * Steps 3 to 6: the document the writer returned, serialized once and bounded as the receiver bounds it once
     * inflated, then deflated and encoded; the query of the binding, signed when a Signing is given; the URL on the
     * Destination, its query bounded as the receiver bounds it.
     *
     * @param Document                     $document         the message, unsigned in XML (B-6)
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message parameter, as the binding names it
     * @param string                       $destination      the message's Destination
     * @param ?string                      $ownQuery         the query the Destination holds, or null (step 1)
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
     * Steps 4 and 5: unsigned, the message parameter and RelayState when given; signed, the octets of B-2, then the
     * signature over them by the key of the Signing, under its algorithm.
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message parameter, as the binding names it
     * @param string                       $message          the message, encoded (step 3)
     * @param ?string                      $relayState       RelayState, encoded, or null when none is given
     *
     * @throws RefusedXml Dsig's SigningFailed and AlgorithmUnavailable
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
     * Step 1: the Destination, an http or an https URL, and the query it already holds, without its "?", or null when
     * it holds none. Its names are read as the receiver reads them (section 6.1 step 2): a name that reads as one of
     * the six parameters of B-1, written so or once percent-decoded, its leading spaces dropped or cut at a NUL or a
     * "[", or a malformed percent-escape, would be refused there, and is refused here.
     *
     * @throws InvalidArgumentException when the Destination is neither an http nor an https URL, holds a fragment, or
     *                                  holds a query the receiver would refuse
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
