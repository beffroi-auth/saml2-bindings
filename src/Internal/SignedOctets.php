<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

/**
 * B-2, SAML Bindings §3.4.4.1
 *
 * Each value is the substring of the query string as it arrived, never decoded and encoded again.
 *
 * @internal
 */
final readonly class SignedOctets
{
    public string $bytes;

    /**
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     */
    public function __construct(string $messageParameter, string $message, ?string $relayState, string $sigAlg)
    {
        $this->bytes = $messageParameter . '=' . $message . ($relayState === null ? '' : '&RelayState=' . $relayState) . '&SigAlg=' . $sigAlg;
    }
}
