<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function dirname;
use function file_get_contents;
use function is_string;
use LogicException;
use function sprintf;

/**
 * The messages the tests of the codec encode and decode, read from tests/Fixture/ as they are on disk: a whole message
 * is a fixture file (section 9.7), and each hostile variant of it is the one change a data provider makes to it.
 * behaviour/authn-request-unsigned.xml is saml2-model's, copied byte for byte from its main at 9c833c5.
 */
trait CodecFixtures
{
    private static function fixture(string $path): string
    {
        $bytes = file_get_contents(dirname(__DIR__, 2) . '/Fixture/' . $path);
        if (! is_string($bytes)) {
            throw new LogicException(sprintf('The fixture %s cannot be read.', $path));
        }

        return $bytes;
    }
}
