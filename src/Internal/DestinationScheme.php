<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use function preg_match;

/**
 * Nothing is trimmed before the scheme is read, so that a leading space or a control character a browser might skip
 * makes the Destination refused.
 *
 * @internal
 */
final readonly class DestinationScheme
{
    public static function isWeb(string $destination): bool
    {
        return preg_match('~^https?:~i', $destination) === 1;
    }
}
