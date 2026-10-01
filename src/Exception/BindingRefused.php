<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

use Beffroi\Xml\Core\Exception\RefusedXml;

/**
 * A query string, a form or a received message the package refuses (section 5.4). It extends the RefusedXml of Core,
 * as the refusals of Dsig and of the model do, so that a consumer that catches that base class catches everything the
 * stack refuses; the refusals of Core, Dsig and the model go through the package as they are. Its message names the
 * rule in parentheses, (B-1) or (section 8), and never carries a value of the input: no parameter's name as received,
 * no value, no RelayState, no URL, no query string, no entity ID, no byte of a message (B-11).
 */
abstract class BindingRefused extends RefusedXml
{
}
