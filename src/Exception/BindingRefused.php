<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * Its message names the rule, (B-1) or (section 8), and never carries a value of the input (B-11).
 */
abstract class BindingRefused extends RefusedXml
{
}
