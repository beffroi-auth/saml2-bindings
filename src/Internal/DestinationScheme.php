<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function preg_match;

/**
 * The scheme of a Destination, the one place the senders read it (sections 6.3 and 6.4 step 1).
 *
 * A Destination is the head of the location the browser is sent to, or the action of the form it submits, and it comes
 * from the peer's metadata, where the model asks for an absolute URI and no more (M-6): only http and https are
 * locations a browser is to be sent to by a SAML binding. The scheme is read at the first byte, ASCII letters of either
 * case (RFC 3986 §3.1: a scheme is case-insensitive), and nothing is trimmed or normalised to find it, so that what a
 * browser might skip, a leading space or a control character, makes the Destination refused.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class DestinationScheme
{
    /**
     * Whether the Destination starts with the scheme http or https, followed by a colon.
     */
    public static function isWeb(string $destination): bool
    {
        // preg_match() returns 1, 0 or false: only a 1 accepts, a failure of PCRE included.
        return preg_match('~^https?:~i', $destination) === 1;
    }
}
