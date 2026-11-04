<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * B-4: nothing in the query string may name or carry a key.
 */
final class NoVerificationKey extends BindingRefused
{
}
