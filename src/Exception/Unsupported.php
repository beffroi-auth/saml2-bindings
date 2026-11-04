<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * What SAML allows and the package refuses by name, each listed in section 8.
 */
final class Unsupported extends BindingRefused
{
}
