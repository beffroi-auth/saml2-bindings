<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * What SAML allows and the package refuses by name, each listed in section 8: a SAMLEncoding other than DEFLATE, a
 * SigAlg or a Signature in a form.
 */
final class Unsupported extends BindingRefused
{
}
