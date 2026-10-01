<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_map;
use Beffroi\Saml2\Bindings\PostForm;
use function implode;
use function parse_str;
use function urlencode;

/**
 * A form as a browser posts it and as PHP parses it (sections 6.7, 6.8, 9.1): its fields encoded in the body of an
 * application/x-www-form-urlencoded post, in their order, a space as "+" and every byte other than letters, digits,
 * "-", "." and "_" percent-encoded (URL Standard §5), then decoded by PHP's own parser, the one behind the fields a
 * consumer gives PostReceiver ($request->request->all() of HttpFoundation), so that a test gives the receiver what a
 * consumer gives it, a field named "SAMLResponse[]" an array among it. Nothing here calls the package.
 */
final readonly class BrowserForm
{
    /**
     * The body a browser posts for $fields, each name and value in order.
     *
     * @param list<array{string, string}> $fields
     */
    public static function body(array $fields): string
    {
        return implode('&', array_map(
            static fn (array $field): string => urlencode($field[0]) . '=' . urlencode($field[1]),
            $fields,
        ));
    }

    /**
     * The fields PHP's parser decodes from $body, as the consumer gives them to PostReceiver (section 6.8).
     *
     * @return array<array-key, mixed>
     */
    public static function parsed(string $body): array
    {
        parse_str($body, $fields);

        return $fields;
    }

    /**
     * $fields, posted by a browser and parsed by PHP.
     *
     * @param list<array{string, string}> $fields
     *
     * @return array<array-key, mixed>
     */
    public static function posted(array $fields): array
    {
        return self::parsed(self::body($fields));
    }

    /**
     * The fields of $form, in its order, posted by a browser to its action and parsed by PHP: what the consumer of the
     * peer gives its PostReceiver (section 6.7).
     *
     * @return array<array-key, mixed>
     */
    public static function submitted(PostForm $form): array
    {
        $fields = [];
        foreach ($form->fields as $name => $value) {
            $fields[] = [$name, $value];
        }

        return self::posted($fields);
    }
}
