<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * A message received over HTTP-Redirect whose root holds a ds:Signature child, whether the query string is signed or
 * not: the binding removes the XML signature before encoding (SAML Bindings section 3.4.4.1 step 1), and a signature the
 * binding never verifies is one a reader might (B-6).
 */
final class XmlSignatureRefused extends BindingRefused
{
}
