<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

/**
 * The octets the detached signature of HTTP-Redirect covers (B-2, SAML Bindings §3.4.4.1, steps 2 and 3 of the
 * signature and the note that follows them): the message parameter, SAMLRequest or SAMLResponse, and its value; then
 * RelayState and its value when the query string carries one; then SigAlg and its value. Each value is the substring of
 * the query string exactly as it arrived, still percent-encoded, nothing decoded and encoded again; the parameters are
 * in that order whatever the order of arrival, and nothing else is in them, neither Signature nor SAMLEncoding nor any
 * other parameter (section 6.1 step 7). On emission, the same octets from the values the package encoded (section 6.3
 * step 4).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class SignedOctets
{
    /**
     * The octets, as the signature covers them.
     */
    public string $bytes;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter the message parameter, as the binding names it
     * @param string                       $message          its value, still percent-encoded
     * @param ?string                      $relayState       the value of RelayState, still percent-encoded, or null
     *                                                       when the query string carries none
     * @param string                       $sigAlg           the value of SigAlg, still percent-encoded
     */
    public function __construct(string $messageParameter, string $message, ?string $relayState, string $sigAlg)
    {
        $this->bytes =
            $messageParameter
            . '='
            . $message
            . ($relayState === null ? '' : '&RelayState=' . $relayState)
            . '&SigAlg='
            . $sigAlg;
    }
}
