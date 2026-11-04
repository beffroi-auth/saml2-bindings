<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;

/**
 * @internal
 */
enum Service
{
    case SingleSignOn;
    case SingleLogout;
    case AssertionConsumer;

    /**
     * Sections 6.1 step 3 and 6.2 step 2
     *
     * @return non-empty-list<'SAMLRequest'|'SAMLResponse'>
     */
    public function messageParameters(): array
    {
        return match ($this) {
            self::SingleSignOn => ['SAMLRequest'],
            self::SingleLogout => ['SAMLRequest', 'SAMLResponse'],
            self::AssertionConsumer => ['SAMLResponse'],
        };
    }

    /**
     * Sections 6.1 step 11 and 6.2 step 6
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter one of messageParameters()
     *
     * @throws MalformedMessage
     * @throws MixedContent
     */
    public function read(
        string $messageParameter,
        Document $document,
    ): UnverifiedAuthnRequest|UnverifiedLogoutRequest|UnverifiedLogoutResponse|UnverifiedResponse {
        return match (true) {
            $this === self::SingleSignOn => UnverifiedAuthnRequest::of($document),
            $this === self::AssertionConsumer => UnverifiedResponse::of($document),
            $messageParameter === 'SAMLRequest' => UnverifiedLogoutRequest::of($document),
            default => UnverifiedLogoutResponse::of($document),
        };
    }
}
