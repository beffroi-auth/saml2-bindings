<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * A received RelayState empty, or longer than the 80 bytes of SAML Bindings sections 3.4.3 and 3.5.3 once decoded
 * (B-9). A length the specification fixes is a rule of the value, not a bound: it is never LimitExceeded.
 */
final class InvalidRelayState extends BindingRefused
{
}
