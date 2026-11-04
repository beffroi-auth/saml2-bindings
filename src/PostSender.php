<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Bindings\Internal\DestinationScheme;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Serializer;
use InvalidArgumentException;
use SensitiveParameter;
use function sprintf;
use function strlen;

/**
 * Section 6.4
 *
 * The arguments are checked first, so that the signing key is never called for a form the sender then refuses.
 */
final readonly class PostSender
{
    /**
     * B-9: a named exception to the 80 bytes of SAML Bindings §3.4.3 and §3.5.3.
     */
    private const int MAX_RELAY_STATE_BYTES = 1_024;

    public function __construct(
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * @param ?string $relayState the one the request carried, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9 or a Destination that is not an http or https URL
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function response(
        Response $response,
        #[SensitiveParameter]
        Signing $signing,
        SignedParts $parts = SignedParts::Assertion,
        ?string $relayState = null,
        ?Encryption $encryption = null,
    ): PostForm {
        $destination = $this->arguments($response->destination, 'Response', $relayState);

        return $this->form(
            new ResponseWriter()->write($response, $signing, $parts, $encryption),
            'SAMLResponse',
            $destination,
            $relayState,
        );
    }

    /**
     * @param ?string $relayState the one the request carried, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9 or a Destination that is not an http or https URL
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function failure(
        Response $response,
        #[SensitiveParameter]
        ?Signing $signing,
        ?string $relayState = null,
    ): PostForm {
        $destination = $this->arguments($response->destination, 'Response', $relayState);

        return $this->form(
            new ResponseWriter()->writeFailure($response, $signing),
            'SAMLResponse',
            $destination,
            $relayState,
        );
    }

    /**
     * @param ?Signing $signing    null only when neither party's metadata wants the request signed
     * @param ?string  $relayState at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9 or a Destination that is not an http or https URL
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function authnRequest(
        AuthnRequest $request,
        #[SensitiveParameter]
        ?Signing $signing,
        ?string $relayState = null,
    ): PostForm {
        $destination = $this->arguments($request->destination, 'AuthnRequest', $relayState);

        return $this->form(
            new AuthnRequestWriter()->write($request, $signing),
            'SAMLRequest',
            $destination,
            $relayState,
        );
    }

    /**
     * @param ?string $relayState at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function logoutRequest(
        LogoutRequest $request,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): PostForm {
        $destination = $this->arguments($request->destination, 'LogoutRequest', $relayState);

        return $this->form(
            new LogoutRequestWriter()->write($request, $signing),
            'SAMLRequest',
            $destination,
            $relayState,
        );
    }

    /**
     * @param ?string $relayState the one the request carried, at most 1 024 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException for a RelayState outside B-9
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    public function logoutResponse(
        LogoutResponse $response,
        #[SensitiveParameter]
        Signing $signing,
        ?string $relayState = null,
    ): PostForm {
        $destination = $this->arguments($response->destination, 'LogoutResponse', $relayState);

        return $this->form(
            new LogoutResponseWriter()->write($response, $signing),
            'SAMLResponse',
            $destination,
            $relayState,
        );
    }

    /**
     * Section 6.4 step 1
     *
     * @param string $message the name of the message, for the refusal
     *
     * @return string the Destination
     *
     * @throws InvalidArgumentException
     */
    private function arguments(?string $destination, string $message, ?string $relayState): string
    {
        if ($destination === null) {
            throw new InvalidArgumentException(sprintf(
                'The %s holds no Destination, the action of the form (section 6.4).',
                $message,
            ));
        }
        if (! DestinationScheme::isWeb($destination)) {
            throw new InvalidArgumentException('The Destination is neither an http nor an https URL, the only actions a form is submitted to (section 6.4).');
        }
        if ($relayState === '') {
            throw new InvalidArgumentException('The RelayState is empty (B-9).');
        }
        if ($relayState !== null && strlen($relayState) > self::MAX_RELAY_STATE_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'The RelayState is longer than %d bytes (B-9).',
                self::MAX_RELAY_STATE_BYTES,
            ));
        }

        return $destination;
    }

    /**
     * Section 6.4 steps 3 and 4
     *
     * @param 'SAMLRequest'|'SAMLResponse' $field
     *
     * @throws LimitExceeded
     * @throws RefusedXml
     */
    private function form(Document $document, string $field, string $action, ?string $relayState): PostForm
    {
        $value = Base64::encode(new Serializer()->serialize($document));
        if (strlen($value) > $this->limits->maxFormValueBytes) {
            throw new LimitExceeded(sprintf(
                'The message would be longer than maxFormValueBytes, %d bytes, once encoded, which the receiver refuses (B-7).',
                $this->limits->maxFormValueBytes,
            ));
        }

        return new PostForm(
            $action,
            $relayState === null ? [$field => $value] : [$field => $value, 'RelayState' => $relayState],
        );
    }
}
