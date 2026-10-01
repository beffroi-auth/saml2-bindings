<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * A signed query string from a peer whose role in its metadata holds no signing certificate: nothing verifies it, and
 * nothing in the query string may name or carry a key (B-4).
 */
final class NoVerificationKey extends BindingRefused
{
}
