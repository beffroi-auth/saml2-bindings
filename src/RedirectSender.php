<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Bindings\Internal\Deflater;
use Beffroi\Saml2\Bindings\Internal\Percent;
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
use function in_array;
use InvalidArgumentException;
use LogicException;
use SensitiveParameter;
use function sprintf;
use function str_contains;
use function strlen;
use function strpos;
use function substr;

/**
 * HTTP-Redirect sent, in the order of section 6.3 (section 5.3): the RelayState checked (B-9), the message written by
 * the model's writer with no Signing, so that it carries no XML signature (B-6), serialized once by Core's Serializer
 * (B-10), raw-deflated, base64-encoded on one line and percent-encoded in uppercase hexadecimal (B-8), then, when a
 * Signing is given, the octets of B-2 signed through the Dsig signing port of the Signing, and the URL built on the
 * message's Destination. Only what the profiles let travel: an AuthnRequest, signed or not, and the two logout messages,
 * always signed; no method sends a Response (B-12).
 */
final readonly class RedirectSender
{
    /**
     * SAML Bindings §3.4.3 (B-9).
     */
    private const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * The six parameters of B-1, which a Destination's own query never holds (section 6.3 step 6).
     */
    private const array PARAMETERS = [
        'SAMLRequest',
        'SAMLResponse',
        'RelayState',
        'SigAlg',
        'Signature',
        'SAMLEncoding',
    ];

    /**
     * @param BindingLimits $limits maxQueryStringBytes, the bound of the receiver the query string is written for
     *                              (section 7)
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
     * @param ?string  $relayState opaque, at most 80 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination that
     *                                  holds a fragment or a query the receiver would refuse (section 6.3 step 6),
     *                                  what the writer refuses so, a request without Destination among it
     * @throws LimitExceeded            a query string longer than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
     */
    public function authnRequest(
        AuthnRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
        ?string $relayState = null,
    ): string {
        $this->checkRelayState($relayState);

        return $this->url(
            new AuthnRequestWriter()->write($request, null),
            'SAMLRequest',
            $request->destination ?? throw new LogicException('The writer wrote an AuthnRequest without Destination (section 6.3).'),
            $relayState,
            $signing,
        );
    }

    /**
     * The same, a LogoutRequest in SAMLRequest, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 80 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination that
     *                                  holds a fragment or a query the receiver would refuse (section 6.3 step 6),
     *                                  what the writer refuses so
     * @throws LimitExceeded            a query string longer than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
     */
    public function logoutRequest(
        LogoutRequest $request,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): string {
        $this->checkRelayState($relayState);

        return $this->url(
            new LogoutRequestWriter()->write($request, null),
            'SAMLRequest',
            $request->destination,
            $relayState,
            $signing,
        );
    }

    /**
     * The same, a LogoutResponse in SAMLResponse, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 80 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination that
     *                                  holds a fragment or a query the receiver would refuse (section 6.3 step 6)
     * @throws LimitExceeded            a query string longer than maxQueryStringBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
     */
    public function logoutResponse(
        LogoutResponse $response,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): string {
        $this->checkRelayState($relayState);

        return $this->url(
            new LogoutResponseWriter()->write($response, null),
            'SAMLResponse',
            $response->destination,
            $relayState,
            $signing,
        );
    }

    /**
     * Step 1: a RelayState, when given, neither empty nor longer than 80 bytes (B-9).
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
     * Steps 3 to 6: the document the writer returned, serialized once, deflated, encoded; the query of the binding,
     * signed when a Signing is given; the URL on the Destination, bounded as the receiver bounds it.
     *
     * @param Document                     $document         the message, unsigned in XML (B-6)
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message parameter, as the binding names it
     * @param string                       $destination      the message's Destination
     *
     * @throws InvalidArgumentException
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    private function url(
        Document $document,
        string $messageParameter,
        string $destination,
        ?string $relayState,
        #[SensitiveParameter]
        ?Signing $signing,
    ): string {
        $query = $this->query(
            $messageParameter,
            Percent::encode(Base64::encode(Deflater::deflate(new Serializer()->serialize($document)))),
            $relayState === null ? null : Percent::encode($relayState),
            $signing,
        );
        $ownQuery = $this->ownQuery($destination);
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
     * Step 6: the query the Destination already holds, without its "?", or null when it holds none. Its names are read
     * as the receiver reads them (section 6.1 step 2): one of the six parameters of B-1, under its name or a
     * percent-encoded spelling of it, or a malformed percent-escape, would be refused there, and is refused here.
     *
     * @throws InvalidArgumentException when the Destination holds a fragment, or a query the receiver would refuse
     */
    private function ownQuery(string $destination): ?string
    {
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
                $name = Percent::decode(explode('=', $segment)[0]);
            } catch (MalformedEncoding $malformed) {
                throw new InvalidArgumentException(
                    'The query of the Destination holds a malformed percent-escape in a name, which the receiver refuses (B-8).',
                    $malformed->getCode(),
                    previous: $malformed,
                );
            }
            if (in_array($name, self::PARAMETERS, true)) {
                throw new InvalidArgumentException('The query of the Destination holds a parameter of the binding (B-1).');
            }
        }

        return $query;
    }
}
