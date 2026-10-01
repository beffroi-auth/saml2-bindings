<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Exception;

/**
 * A value is not in the one lexical form the package reads (B-8): a malformed percent-escape; base64 out of the
 * alphabet of RFC 4648 section 4, without its padding, with a set unused bit or with whitespace where none is allowed;
 * DEFLATE that is not raw, is cut before its final block or has bytes after it; or a value that is empty where the
 * binding needs one.
 */
final class MalformedEncoding extends BindingRefused
{
}
