<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_decode;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Dsig\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\SigningKeyInterface;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use Beffroi\Xml\Dsig\Verifier;
use DateTimeImmutable;
use function explode;
use function get_class_methods;
use function gzinflate;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rawurldecode;
use function strlen;
use Throwable;

/**
 * Section 6.3, B-2, B-6, B-8, B-9, B-10, B-12: what RedirectSender writes, read back from the URL it returns with PHP's
 * own decoders and Dsig's Verifier, and what it refuses before it writes anything a receiver would refuse: the rows of
 * sections 9.2 and 9.3 that are the sender's. That every URL it writes is received, verified and validated is
 * RedirectRoundTripTest's; that an implementation which is not PHP verifies its signatures and inflates its messages
 * is the OpenSSL oracle's (section 9.1). SAML Bindings §3.4.4.1.
 *
 * @phpstan-import-type Message from SendingFixtures
 */
final class RedirectSenderTest extends TestCase
{
    use SendingFixtures;

    /**
     * §9.3 row 11, B-2, section 6.3 steps 4 and 5, SAML Bindings §3.4.4.1: the query holds the message parameter, then
     * RelayState when given, then SigAlg and Signature when signed, in that order and nothing else.
     *
     * @param Message      $message
     * @param list<string> $names
     */
    #[Test]
    #[DataProvider('provideQueries')]
    public function itWritesTheParametersInTheOrderOfTheBinding(
        string $message,
        ?string $relayState,
        array $names,
    ): void {
        // When
        $url = self::send($message, $relayState);

        // Then
        static::assertSame($names, self::query($url)->names());
    }

    /**
     * @return iterable<string, array{Message, ?string, list<string>}>
     */
    public static function provideQueries(): iterable
    {
        yield 'an unsigned AuthnRequest' => ['an unsigned AuthnRequest', null, ['SAMLRequest']];
        yield 'an unsigned AuthnRequest, with RelayState' => [
            'an unsigned AuthnRequest',
            self::RELAY_STATE,
            ['SAMLRequest', 'RelayState'],
        ];
        yield 'an AuthnRequest' => ['an AuthnRequest', null, ['SAMLRequest', 'SigAlg', 'Signature']];
        yield 'an AuthnRequest, with RelayState' => [
            'an AuthnRequest',
            self::RELAY_STATE,
            ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'],
        ];
        yield 'a LogoutRequest' => ['a LogoutRequest', null, ['SAMLRequest', 'SigAlg', 'Signature']];
        yield 'a LogoutRequest, with RelayState' => [
            'a LogoutRequest',
            self::RELAY_STATE,
            ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'],
        ];
        yield 'a LogoutResponse' => ['a LogoutResponse', null, ['SAMLResponse', 'SigAlg', 'Signature']];
        yield 'a LogoutResponse, with RelayState' => [
            'a LogoutResponse',
            self::RELAY_STATE,
            ['SAMLResponse', 'RelayState', 'SigAlg', 'Signature'],
        ];
    }

    /**
     * §9.3 row 11, B-6, B-10, section 6.3 steps 2 and 3, SAML Bindings §3.4.4.1 steps 1 and 2: the message is the
     * document the model's writer wrote with no Signing, serialized once, raw-deflated (RFC 1951): zlib's reader of raw
     * DEFLATE, a reader of neither wrapper, gives back the writer's very bytes, without any XML signature.
     *
     * @param Message                      $message
     * @param 'SAMLRequest'|'SAMLResponse' $parameter
     */
    #[Test]
    #[DataProvider('provideMessages')]
    public function itCarriesTheDocumentTheWriterWroteUnsignedAndRawDeflated(
        string $message,
        string $parameter,
        string $written,
    ): void {
        // Given
        $value = self::query(self::send($message))->value($parameter);

        // When
        $inflated = gzinflate((string) base64_decode(rawurldecode($value), true));

        // Then
        static::assertSame(self::fixture($written), $inflated);
    }

    /**
     * @return iterable<string, array{Message, 'SAMLRequest'|'SAMLResponse', string}>
     */
    public static function provideMessages(): iterable
    {
        yield 'an unsigned AuthnRequest' => ['an unsigned AuthnRequest', 'SAMLRequest', self::AUTHN_REQUEST_WRITTEN];
        yield 'an AuthnRequest' => ['an AuthnRequest', 'SAMLRequest', self::AUTHN_REQUEST_WRITTEN];
        yield 'a LogoutRequest' => ['a LogoutRequest', 'SAMLRequest', self::LOGOUT_REQUEST];
        yield 'a LogoutResponse' => ['a LogoutResponse', 'SAMLResponse', self::LOGOUT_RESPONSE];
    }

    /**
     * §9.3 row 11, B-8, section 6.3 steps 3 and 5, SAML Bindings §3.4.4.1 step 3: the message and the signature are
     * base64 on one line, without whitespace, its three characters outside the unreserved ones of RFC 3986, +, / and
     * =, escaped in uppercase hexadecimal and nothing else escaped.
     *
     * @param 'SAMLRequest'|'Signature' $parameter
     */
    #[Test]
    #[DataProvider('provideBase64Parameters')]
    public function itWritesBase64OnOneLineEscapedInUppercase(string $parameter): void
    {
        // When
        $value = self::query(self::send('an AuthnRequest'))->value($parameter);

        // Then
        static::assertMatchesRegularExpression('~\A(?:[A-Za-z0-9]|%2B|%2F)+(?:%3D){0,2}\z~', $value);
    }

    /**
     * @return iterable<string, array{'SAMLRequest'|'Signature'}>
     */
    public static function provideBase64Parameters(): iterable
    {
        yield 'SAMLRequest' => ['SAMLRequest'];
        yield 'Signature' => ['Signature'];
    }

    /**
     * §9.3 row 11, B-8, B-9, section 6.3 steps 3 and 4, RFC 3986 §2.1 and §2.3: RelayState is written with every byte
     * outside the unreserved characters escaped in uppercase hexadecimal, as RFC 3986 writes it.
     */
    #[Test]
    public function itEscapesRelayStateInUppercase(): void
    {
        // When
        $url = self::send('an unsigned AuthnRequest', self::RELAY_STATE);

        // Then
        static::assertSame(
            '%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC'
            . '%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC%E2%82%AC'
            . '%20%26%3D%2B%2F%3F%23%25%3B~-._state00',
            self::query($url)->value('RelayState'),
        );
    }

    /**
     * §9.3 row 11, B-3, section 6.3 step 4, RFC 3986 §2.1: SigAlg is the URI of the Signing's algorithm, escaped in
     * uppercase hexadecimal.
     */
    #[Test]
    #[DataProvider('provideAlgorithms')]
    public function itWritesTheAlgorithmOfTheSigning(SignatureAlgorithm $algorithm): void
    {
        // When
        $url = self::send('an AuthnRequest', algorithm: $algorithm);

        // Then
        static::assertSame(RedirectQuery::encode($algorithm->value), self::query($url)->value('SigAlg'));
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (self::algorithms() as $algorithm) {
            yield $algorithm->name => [$algorithm];
        }
    }

    /**
     * B-2, B-3, section 6.3 steps 4 and 5, dsig.md §6.4, SAML Bindings §3.4.4.1: the Signature is the signature, by the
     * key of the Signing under its algorithm, of the octets of the binding, SAMLRequest, RelayState and SigAlg as the
     * URL carries them, which Dsig's Verifier verifies under the certificate of that key.
     */
    #[Test]
    #[DataProvider('provideAlgorithms')]
    public function itSignsTheOctetsOfTheBinding(SignatureAlgorithm $algorithm): void
    {
        // Given
        $query = self::query(self::send('an AuthnRequest', self::RELAY_STATE, algorithm: $algorithm));
        $key = VerificationKey::fromCertificateBase64(TestKeys::certificate('sp'));

        // When
        $verified = new Verifier(SamlLoader::create())->verifyDetached(
            $query->octets(),
            (string) base64_decode(rawurldecode($query->value('Signature')), true),
            $algorithm,
            new VerificationKeys([$key]),
        );

        // Then
        static::assertSame($key, $verified);
    }

    /**
     * §9.3 row 3, section 6.3 step 6, SAML Bindings §3.4.4.1: a Destination that holds its own query, as the Location
     * of an endpoint may, is followed by &, then by the query of the binding.
     */
    #[Test]
    public function itAppendsTheQueryToTheQueryOfTheDestination(): void
    {
        // When
        $url = self::send('an unsigned AuthnRequest', 'state', self::SSO . '?tenant=acme');

        // Then
        static::assertSame(
            [self::SSO . '?tenant=acme', ['tenant', 'SAMLRequest', 'RelayState']],
            [explode('&', $url, 2)[0], self::query($url)->names()],
        );
    }

    /**
     * §9.2 row 33, B-9, section 6.3 step 1, section 8: a RelayState of 1 025 bytes, one over the exception section 8
     * makes to the 80 bytes of SAML Bindings §3.4.3, given to any method, is a programming error of the caller, refused
     * before anything is written.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideEveryMethod')]
    public function itRefusesARelayStateOver1024Bytes(string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The RelayState is longer than 1024 bytes (B-9).');

        // When
        self::send($message, self::longestRelayState() . 'x');
    }

    /**
     * §9.2 row 33, B-9, section 6.3 step 1, section 12: an empty RelayState, given to any method, is a programming
     * error of the caller: absence says the same.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideEveryMethod')]
    public function itRefusesAnEmptyRelayState(string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The RelayState is empty (B-9).');

        // When
        self::send($message, '');
    }

    /**
     * §9.2 row 33, section 6.3 step 1, RFC 3986 §3.5: a Destination holding a fragment, which a URL of HTTP-Redirect
     * does not carry, is a programming error of the caller, whatever the method.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideEveryMethod')]
    public function itRefusesADestinationHoldingAFragment(string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The Destination holds a fragment, which a URL of HTTP-Redirect does not carry (section 6.3).');

        // When
        self::send($message, destination: 'https://peer.example.com/saml#fragment');
    }

    /**
     * @return iterable<string, array{Message}>
     */
    public static function provideEveryMethod(): iterable
    {
        yield 'authnRequest()' => ['an unsigned AuthnRequest'];
        yield 'logoutRequest()' => ['a LogoutRequest'];
        yield 'logoutResponse()' => ['a LogoutResponse'];
    }

    /**
     * §9.2 row 33, B-1, section 6.3 step 1: a Destination whose own query holds one of the six parameters of the
     * binding, under its name or a name PHP's parser reads as it, percent-encoded, after a leading space, followed by a
     * NUL or a "[", first or not, with or without "=", which the receiver would refuse, is a programming error of the
     * caller.
     */
    #[Test]
    #[DataProvider('provideQueriesHoldingAParameterOfTheBinding')]
    public function itRefusesADestinationWhoseQueryHoldsAParameterOfTheBinding(string $destination): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The query of the Destination holds a parameter of the binding (B-1).');

        // When
        self::send('an unsigned AuthnRequest', destination: $destination);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueriesHoldingAParameterOfTheBinding(): iterable
    {
        yield 'SAMLRequest, first' => [self::SSO . '?SAMLRequest=x'];
        yield 'SAMLResponse, after another parameter' => [self::SSO . '?tenant=acme&SAMLResponse=x'];
        yield 'RelayState, without "="' => [self::SSO . '?tenant=acme&RelayState'];
        yield 'SigAlg, empty' => [self::SSO . '?SigAlg='];
        yield 'Signature, between two others' => [self::SSO . '?tenant=acme&Signature=x&lang=fr'];
        yield 'SAMLEncoding' => [self::SSO . '?SAMLEncoding=x'];
        yield 'SAMLRequest, percent-encoded' => [self::SSO . '?SAML%52equest=x'];
        yield 'RelayState, two of its letters percent-encoded' => [self::SSO . '?tenant=acme&Relay%53tat%65=x'];
        yield 'SAMLRequest after a space written +' => [self::SSO . '?+SAMLRequest=x'];
        yield 'SigAlg after a space written %20' => [self::SSO . '?tenant=acme&%20SigAlg=x'];
        yield 'SAMLResponse followed by a NUL' => [self::SSO . '?SAMLResponse%00=x'];
        yield 'RelayState followed by an index' => [self::SSO . '?RelayState[0]=x'];
        yield 'Signature followed by escaped brackets' => [self::SSO . '?Signature%5B%5D=x'];
    }

    /**
     * B-8, section 6.3 step 1: a Destination whose own query holds a malformed percent-escape in a name, which the
     * receiver would refuse, is a programming error of the caller.
     */
    #[Test]
    #[DataProvider('provideQueriesWithAMalformedEscapeInAName')]
    public function itRefusesADestinationWhoseQueryHoldsAMalformedEscapeInAName(string $destination): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The query of the Destination holds a malformed percent-escape in a name, which the receiver refuses (B-8).');

        // When
        self::send('an unsigned AuthnRequest', destination: $destination);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueriesWithAMalformedEscapeInAName(): iterable
    {
        yield 'not hexadecimal, first' => [self::SSO . '?a%G1=1'];
        yield 'one digit, after another parameter' => [self::SSO . '?tenant=acme&a%2=1'];
        yield 'a trailing %, without "="' => [self::SSO . '?tenant=acme&a%'];
    }

    /**
     * Section 6.1 step 2, section 6.3 step 1: a value of the Destination's own query is not decoded, as the receiver
     * decodes no value of a parameter that is not the binding's, and a malformed escape in it is sent as it is.
     */
    #[Test]
    public function itLeavesTheValuesOfTheQueryOfTheDestinationAsTheyAre(): void
    {
        // When
        $url = self::send('an unsigned AuthnRequest', destination: self::SSO . '?tenant=%G1');

        // Then
        static::assertSame(self::SSO . '?tenant=%G1', explode('&', $url, 2)[0]);
    }

    /**
     * Section 7, section 6.3 step 6: a query string exactly as long as maxQueryStringBytes, the query of the
     * Destination and its "&" included, is sent, since the receiver accepts it.
     */
    #[Test]
    #[DataProvider('provideDestinations')]
    public function itSendsAQueryStringOfExactlyTheBound(string $destination): void
    {
        // Given
        $bytes = strlen(self::queryString(self::send('an unsigned AuthnRequest', destination: $destination)));

        // When
        $url = self::send(
            'an unsigned AuthnRequest',
            destination: $destination,
            limits: new BindingLimits(maxQueryStringBytes: $bytes),
        );

        // Then
        static::assertSame($bytes, strlen(self::queryString($url)));
    }

    /**
     * §9.2 row 34, B-7, section 6.3 step 6: a query string one byte longer than maxQueryStringBytes, the query of the
     * Destination and its "&" included, which the receiver would refuse, is refused.
     */
    #[Test]
    #[DataProvider('provideDestinations')]
    public function itRefusesAQueryStringOverTheBound(string $destination): void
    {
        // Given
        $bound = strlen(self::queryString(self::send('an unsigned AuthnRequest', destination: $destination))) - 1;

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The query string would be longer than maxQueryStringBytes, '
        . $bound
        . ' bytes, which the receiver refuses (B-7).');

        // When
        self::send(
            'an unsigned AuthnRequest',
            destination: $destination,
            limits: new BindingLimits(maxQueryStringBytes: $bound),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDestinations(): iterable
    {
        yield 'a Destination without query' => [self::SSO];
        yield 'a Destination holding its own query' => [self::SSO . '?tenant=acme'];
    }

    /**
     * Section 6.3 step 3, B-7: a message whose serialized bytes are exactly maxInflatedBytes long is sent, and the
     * package's receiver, under the same bounds, inflates and reads it.
     */
    #[Test]
    public function itSendsAMessageOfExactlyMaxInflatedBytesWhichTheReceiverReads(): void
    {
        // Given
        $limits = new BindingLimits(maxInflatedBytes: strlen(self::fixture(self::AUTHN_REQUEST_WRITTEN)));
        $url = self::send('an AuthnRequest', limits: $limits);

        // When
        $received = new RedirectReceiver(SamlLoader::create(), $limits)->authnRequest(self::queryString($url));

        // Then
        static::assertSame('https://sp.example.com/saml', $received->request->issuer);
    }

    /**
     * §9.2 row 34, B-7, section 6.3 step 3: a message whose serialized bytes are one byte longer than maxInflatedBytes,
     * which the package's receiver would refuse while inflating it, is refused before it is deflated, whatever the
     * method.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideMessagesOneByteOverTheInflatedBound')]
    public function itRefusesAMessageOverMaxInflatedBytes(string $message, string $written): void
    {
        // Given
        $bound = strlen(self::fixture($written)) - 1;

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The message is longer than maxInflatedBytes, '
        . $bound
        . ' bytes, which the receiver refuses once inflated (B-7).');

        // When
        self::send($message, limits: new BindingLimits(maxInflatedBytes: $bound));
    }

    /**
     * @return iterable<string, array{Message, string}>
     */
    public static function provideMessagesOneByteOverTheInflatedBound(): iterable
    {
        yield 'an unsigned AuthnRequest' => ['an unsigned AuthnRequest', self::AUTHN_REQUEST_WRITTEN];
        yield 'a LogoutRequest' => ['a LogoutRequest', self::LOGOUT_REQUEST];
        yield 'a LogoutResponse' => ['a LogoutResponse', self::LOGOUT_RESPONSE];
    }

    /**
     * §9.2 rows 33 and 34, section 6.3 steps 1 and 3: every refusal that needs nothing but the arguments, and the bound
     * of the serialized message, come before the signature: a key management service is never called for a URL the
     * sender refuses.
     *
     * @param Message                 $message
     * @param class-string<Throwable> $exception
     */
    #[Test]
    #[DataProvider('provideRefusalsBeforeTheKey')]
    public function itNeverCallsTheKeyForAUrlItRefuses(
        string $message,
        ?string $relayState,
        ?string $destination,
        BindingLimits $limits,
        string $exception,
        string $refusal,
    ): void {
        // Given
        $signing = $this->uncalledSigning();

        // Then
        $this->expectException($exception);
        $this->expectExceptionMessageIs($refusal);

        // When
        self::send($message, $relayState, $destination, limits: $limits, signing: $signing);
    }

    /**
     * @return iterable<string, array{Message, ?string, ?string, BindingLimits, class-string<Throwable>, string}>
     */
    public static function provideRefusalsBeforeTheKey(): iterable
    {
        $limits = new BindingLimits();

        yield 'a RelayState of 1 025 bytes, an AuthnRequest' => [
            'an AuthnRequest',
            self::longestRelayState() . 'x',
            null,
            $limits,
            InvalidArgumentException::class,
            'The RelayState is longer than 1024 bytes (B-9).',
        ];
        yield 'an empty RelayState, a LogoutRequest' => [
            'a LogoutRequest',
            '',
            null,
            $limits,
            InvalidArgumentException::class,
            'The RelayState is empty (B-9).',
        ];
        yield 'a Destination holding a fragment, a LogoutResponse' => [
            'a LogoutResponse',
            null,
            self::IDP_SLO . '#fragment',
            $limits,
            InvalidArgumentException::class,
            'The Destination holds a fragment, which a URL of HTTP-Redirect does not carry (section 6.3).',
        ];
        yield 'a parameter of the binding in the query of the Destination, a LogoutRequest' => [
            'a LogoutRequest',
            null,
            self::SP_SLO . '?Signature=x',
            $limits,
            InvalidArgumentException::class,
            'The query of the Destination holds a parameter of the binding (B-1).',
        ];
        yield 'a malformed escape in a name of the query of the Destination, an AuthnRequest' => [
            'an AuthnRequest',
            null,
            self::SSO . '?a%G1=1',
            $limits,
            InvalidArgumentException::class,
            'The query of the Destination holds a malformed percent-escape in a name, which the receiver refuses (B-8).',
        ];
        yield 'a message over maxInflatedBytes, a LogoutResponse' => [
            'a LogoutResponse',
            null,
            null,
            new BindingLimits(maxInflatedBytes: 100),
            LimitExceeded::class,
            'The message is longer than maxInflatedBytes, 100 bytes, which the receiver refuses once inflated (B-7).',
        ];
    }

    /**
     * §9.2 row 33, section 6.3 step 1, M-15: an AuthnRequest without Destination, the URL it is sent to, is a
     * programming error of the caller, refused before its writer runs and before the key is called.
     */
    #[Test]
    public function itRefusesAnAuthnRequestWithoutDestination(): void
    {
        // Given
        $signing = $this->uncalledSigning();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The AuthnRequest holds no Destination, the URL it is sent to (section 6.3).');

        // When
        new RedirectSender()->authnRequest(self::authnRequest(null), $signing);
    }

    /**
     * Section 6.3 step 2, M-15: what the model's writer refuses, a LogoutRequest whose NotOnOrAfter is not later than
     * its IssueInstant, is refused as the writer refuses it, a programming error of the caller, before the key is
     * called.
     */
    #[Test]
    public function itLetsTheRefusalOfTheWriterThrough(): void
    {
        // Given
        $instant = new DateTimeImmutable('2026-09-30T12:00:00Z');
        $request = new LogoutRequest(
            self::LOGOUT_REQUEST_ID,
            $instant,
            new Issuer('https://idp.example.com/saml'),
            self::SP_SLO,
            $instant,
            new NameId('_7a2f4c1d9e'),
        );
        $signing = $this->uncalledSigning();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The NotOnOrAfter of the LogoutRequest is not later than its IssueInstant, to the second, which its reader refuses (section 6.6).');

        // When
        new RedirectSender()->logoutRequest($request, $signing);
    }

    /**
     * §9.3 row 13, B-3, dsig.md §5.1: RSASSA-PSS on a build without PHP 8.5 and OpenSSL 3.1, PHP 8.4 among them, is
     * the signing key's AlgorithmUnavailable, as Dsig refuses it.
     */
    #[Test]
    public function itLetsTheRefusalOfTheSigningKeyThrough(): void
    {
        // Given
        if (SignatureAlgorithm::RsaPssSha256->isAvailable()) {
            static::markTestSkipped('This build signs RSASSA-PSS: PHP 8.5 and OpenSSL 3.1.');
        }

        // Then
        $this->expectException(AlgorithmUnavailable::class);
        $this->expectExceptionMessageIs('This build cannot produce RSASSA-PSS: it needs PHP 8.5 and OpenSSL 3.1 (section 13).');

        // When
        self::send('an AuthnRequest', algorithm: SignatureAlgorithm::RsaPssSha256);
    }

    /**
     * B-12, SAML Profiles §4.1.2: the sender sends an AuthnRequest, a LogoutRequest and a LogoutResponse, and has no
     * method for a Response, which HTTP-Redirect must not carry.
     */
    #[Test]
    public function itHasNoMethodForAResponse(): void
    {
        // When
        $methods = get_class_methods(RedirectSender::class);

        // Then
        static::assertSame(['__construct', 'authnRequest', 'logoutRequest', 'logoutResponse'], $methods);
    }

    /**
     * A Signing whose key fails the test if the sender calls it.
     */
    private function uncalledSigning(): Signing
    {
        $key = $this->createMock(SigningKeyInterface::class);
        $key->expects($this->never())->method('sign');

        return new Signing($key);
    }
}
