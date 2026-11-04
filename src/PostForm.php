<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

/**
 * Nothing is escaped for HTML: the page that renders the form escapes the action and every value (section 6.7).
 */
final readonly class PostForm
{
    /**
     * @param array<string, string> $fields SAMLRequest or SAMLResponse, then RelayState when given
     */
    public function __construct(
        public string $action,
        public array $fields,
    ) {
    }
}
