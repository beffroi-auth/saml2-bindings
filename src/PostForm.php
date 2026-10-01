<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

/**
 * The form PostSender writes (sections 5.3, 6.4): the URL the browser posts to and the fields it posts, in their
 * order. The page that holds it is the consumer's (section 6.7): it escapes the action and every value for an HTML
 * attribute, submits by a script its content security policy allows, and offers a button inside noscript. Nothing here
 * is escaped for HTML.
 */
final readonly class PostForm
{
    /**
     * @param string                $action the message's Destination
     * @param array<string, string> $fields SAMLRequest or SAMLResponse, then RelayState when given; the values as they
     *                                      go on the wire, not escaped for HTML (section 6.7)
     */
    public function __construct(
        public string $action,
        public array $fields,
    ) {
    }
}
