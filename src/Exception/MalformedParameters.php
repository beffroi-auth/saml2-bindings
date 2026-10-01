<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * The parameters of a query string or the fields of a form are not those the binding reads: both message parameters or
 * neither, a message parameter the method does not take, one of the six parameters of B-1 twice, under a percent-encoded
 * name or without "=", a field that is an array (B-1); a Signature without SigAlg, or a SigAlg without Signature (B-3).
 */
final class MalformedParameters extends BindingRefused
{
}
