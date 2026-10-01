<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Internal;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutRequest;
use Beffroi\Saml2\Model\Protocol\UnverifiedLogoutResponse;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\MixedContent;

/**
 * The service of ours at which a message arrives, which the method the consumer calls names (section 2): the message
 * parameters it takes and the message it reads, an AuthnRequest at a single sign-on service, a LogoutRequest or a
 * LogoutResponse at a single logout service (section 6.1 steps 3 and 11). The package reads no SAML element: the
 * model's Unverified*::of() checks the root.
 *
 * @internal outside the compatibility promise of section 5
 */
enum Service
{
    case SingleSignOn;
    case SingleLogout;

    /**
     * Section 6.1 step 3: the message parameters the service takes.
     *
     * @return non-empty-list<'SAMLRequest'|'SAMLResponse'>
     */
    public function messageParameters(): array
    {
        return match ($this) {
            self::SingleSignOn => ['SAMLRequest'],
            self::SingleLogout => ['SAMLRequest', 'SAMLResponse'],
        };
    }

    /**
     * Section 6.1 step 11: the model's unverified message, by service and by message parameter.
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter one of messageParameters()
     *
     * @throws MalformedMessage when the root is not the message the service and the parameter expect
     * @throws MixedContent     when the Issuer holds an element
     */
    public function read(
        string $messageParameter,
        Document $document,
    ): UnverifiedAuthnRequest|UnverifiedLogoutRequest|UnverifiedLogoutResponse {
        return match (true) {
            $this === self::SingleSignOn => UnverifiedAuthnRequest::of($document),
            $messageParameter === 'SAMLRequest' => UnverifiedLogoutRequest::of($document),
            default => UnverifiedLogoutResponse::of($document),
        };
    }
}
