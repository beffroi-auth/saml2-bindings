<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * The binding removes the XML signature before encoding (SAML Bindings §3.4.4.1 step 1): one it never verifies is one
 * a reader might (B-6).
 */
final class XmlSignatureRefused extends BindingRefused
{
}
