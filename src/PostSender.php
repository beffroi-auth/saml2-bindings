<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings;

use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Internal\Base64;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
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
 * HTTP-POST sent, in the order of section 6.4 (section 5.3): first every check that needs nothing but the arguments,
 * the RelayState (B-9) and the message's Destination, the form's action, so that the signing key is never called for a
 * form the sender refuses for them; then the message written and signed in XML by the model's writer with the Signing
 * given (B-12), serialized once by Core's Serializer (B-10), base64-encoded on one line, never deflated (B-8), and
 * bounded as the receiver bounds it (B-7); then the form, the Destination as its action, the message field and
 * RelayState, nothing escaped for HTML (section 6.7). What it writes, the package's receiver reads under the same
 * BindingLimits. Only what the profiles let travel signed: the response's assertion always, and the two logout messages
 * (B-12).
 */
final readonly class PostSender
{
    /**
     * SAML Bindings §3.5.3 (B-9).
     */
    private const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * @param BindingLimits $limits maxFormValueBytes, the bound of the receiver the form is written for (section 7)
     */
    public function __construct(
        private BindingLimits $limits = new BindingLimits(),
    ) {
    }

    /**
     * The form the browser posts: the response's Destination as its action, then SAMLResponse, and RelayState when
     * given (section 6.4). The response, its assertion signed, the response too on request (model.md section 5.7).
     *
     * @param Signing     $signing    the identity provider's
     * @param SignedParts $parts      the assertion alone by default, or the response too
     * @param ?string     $relayState opaque, at most 80 bytes, never empty, the one the request carried (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination
     *                                  missing (section 6.4 step 1), what the writer refuses so
     * @throws LimitExceeded            a base64 text longer than maxFormValueBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
     */
    public function response(
        Response $response,
        #[SensitiveParameter]
        Signing $signing,
        SignedParts $parts = SignedParts::Assertion,
        ?string $relayState = null,
    ): PostForm {
        $destination = $this->arguments($response->destination, 'Response', $relayState);

        return $this->form(
            new ResponseWriter()->write($response, $signing, $parts),
            'SAMLResponse',
            $destination,
            $relayState,
        );
    }

    /**
     * The same, a response whose status is not Success, without assertion, signed when $signing is given (SAML
     * Profiles §4.1.4.2).
     *
     * @param ?string $relayState opaque, at most 80 bytes, never empty, the one the request carried (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination
     *                                  missing (section 6.4 step 1), what the writer refuses so
     * @throws LimitExceeded            a base64 text longer than maxFormValueBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * The same, an AuthnRequest in SAMLRequest, signed when $signing is given.
     *
     * @param ?Signing $signing    the service provider's, or null for a request neither party's metadata wants signed
     *                             (section 5.3)
     * @param ?string  $relayState opaque, at most 80 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, a Destination
     *                                  missing (section 6.4 step 1)
     * @throws LimitExceeded            a base64 text longer than maxFormValueBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * The same, a LogoutRequest in SAMLRequest, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 80 bytes, never empty (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9, what the writer
     *                                  refuses so
     * @throws LimitExceeded            a base64 text longer than maxFormValueBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * The same, a LogoutResponse in SAMLResponse, always signed (B-12, SAML Profiles §4.4.4.1).
     *
     * @param ?string $relayState opaque, at most 80 bytes, never empty, the one the request carried (B-9)
     *
     * @throws InvalidArgumentException a programming error of the caller: a RelayState outside B-9
     * @throws LimitExceeded            a base64 text longer than maxFormValueBytes, which the receiver would refuse
     * @throws RefusedXml               what Core's Serializer refuses, Dsig's SigningFailed and AlgorithmUnavailable
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
     * Step 1, what needs nothing but the arguments, before anything is written or signed: the Destination, the form's
     * action, then the RelayState, when given, neither empty nor longer than 80 bytes (B-9).
     *
     * @param ?string $destination the message's Destination
     * @param string  $message     the name of the message, for the refusal
     *
     * @return string the Destination
     *
     * @throws InvalidArgumentException a programming error of the caller
     */
    private function arguments(?string $destination, string $message, ?string $relayState): string
    {
        if ($destination === null) {
            throw new InvalidArgumentException(sprintf(
                'The %s holds no Destination, the action of the form (section 6.4).',
                $message,
            ));
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
     * Steps 3 and 4: the document the writer returned, serialized once, base64-encoded on one line and bounded as the
     * receiver bounds it; the form on the Destination, the message field then RelayState when given.
     *
     * @param Document                     $document the message, signed in XML by its writer
     * @param 'SAMLRequest'|'SAMLResponse' $field    the message field, as the binding names it
     * @param string                       $action   the message's Destination
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
