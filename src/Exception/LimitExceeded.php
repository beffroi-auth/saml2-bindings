<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * An input over its bound of section 7 before anything decodes it, the raw query string, a form value or the text of a
 * Signature, or an inflated message as soon as it would exceed maxInflatedBytes, the bound named in the message (B-7). A
 * message a sender would serialize over maxInflatedBytes, or a query string it would write over maxQueryStringBytes,
 * which the receiver would refuse, is one too.
 */
final class LimitExceeded extends BindingRefused
{
}
