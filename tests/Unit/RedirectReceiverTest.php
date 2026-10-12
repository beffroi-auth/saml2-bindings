<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use function base64_encode;
use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\InvalidRelayState;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\Exception\MalformedEncoding;
use Beffroi\Saml2\Bindings\Exception\MalformedParameters;
use Beffroi\Saml2\Bindings\Exception\Unsupported;
use Beffroi\Saml2\Bindings\Exception\XmlSignatureRefused;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Xml\Core\Exception\DoctypeRefused;
use Beffroi\Xml\Dsig\Exception\UnknownSignatureAlgorithm;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function gzcompress;
use function gzdeflate;
use function gzencode;
use function is_int;
use function is_string;
use LogicException;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function str_repeat;
use function str_replace;
use function strlen;
use function strpos;
use function substr;
use function substr_replace;
use const ZLIB_ENCODING_RAW;

/**
 * Section 6.1 steps 1 to 11, the HTTP-Redirect rows of sections 9.2 and 9.3 that refuse or accept a query string
 * before the consumer validates what it carries: the bound (B-7), the parameters (B-1, B-3), RelayState (B-9), the
 * encodings (B-8), the document (B-10), no XML signature in it (B-6), the message the method expects (M-1). The rows
 * that need the signature verified are asserted with the Received* classes; those whose acceptance means a verified
 * signature are asserted here through validate(), the consumer's one path. SAML Bindings §3.4.4.1.
 */
final class RedirectReceiverTest extends TestCase
{
    use ReceptionFixtures;

    private const string BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    /**
     * §9.2 row 1, B-1, CVE-2025-27773: SAMLRequest and SAMLResponse in one query string, the signature a genuine one
     * of the peer over the SAMLResponse, the SAMLRequest unsigned, in either order, given to either method, are refused
     * before anything is decoded.
     *
     * @param 'authnRequest'|'logoutMessage' $method
     */
    #[Test]
    #[DataProvider('provideBothMessageParameters')]
    public function itRefusesBothMessageParameters(string $method, string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The query string carries both SAMLRequest and SAMLResponse (B-1).');

        // When
        $this->receive($method, $queryString);
    }

    /**
     * @return iterable<string, array{'authnRequest'|'logoutMessage', string}>
     */
    public static function provideBothMessageParameters(): iterable
    {
        $signed = RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))
            ->withRelayState('state')
            ->signed();
        $authnRequest = RedirectQuery::message(self::fixture(self::AUTHN_REQUEST));
        $logoutRequest = RedirectQuery::message(self::fixture(self::LOGOUT_REQUEST));

        yield 'an AuthnRequest first, to authnRequest()' => [
            'authnRequest',
            'SAMLRequest=' . $authnRequest . '&' . $signed->toString(),
        ];
        yield 'an AuthnRequest last, to authnRequest()' => [
            'authnRequest',
            $signed->toString() . '&SAMLRequest=' . $authnRequest,
        ];
        yield 'a LogoutRequest first, to logoutMessage()' => [
            'logoutMessage',
            'SAMLRequest=' . $logoutRequest . '&' . $signed->toString(),
        ];
        yield 'a LogoutRequest last, to logoutMessage()' => [
            'logoutMessage',
            $signed->toString() . '&SAMLRequest=' . $logoutRequest,
        ];
    }

    /**
     * Section 6.1 step 11, M-1, SAML Bindings §3.4.4.1: a SAMLRequest given to authnRequest() is the model's unverified
     * AuthnRequest, its Issuer read, carried over HTTP-Redirect, without RelayState.
     */
    #[Test]
    public function itReceivesAnAuthnRequest(): void
    {
        // When
        $received = self::receiver()->authnRequest(self::authnRequestQuery()->toString());

        // Then
        static::assertSame(
            ['https://sp.example.com/saml', null, Binding::HttpRedirect],
            [$received->request->issuer, $received->relayState, $received->binding],
        );
    }

    /**
     * Section 6.1 step 11, M-1, SAML Bindings §3.4.4.1: a SAMLRequest given to logoutMessage() is the model's
     * unverified LogoutRequest.
     */
    #[Test]
    public function itReceivesALogoutRequest(): void
    {
        // When
        $received = self::receiver()
            ->logoutMessage(
                RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST))->toString(),
            );

        // Then
        static::assertInstanceOf(ReceivedLogoutRequest::class, $received);
        static::assertSame(
            ['https://idp.example.com/saml', Binding::HttpRedirect],
            [$received->request->issuer, $received->binding],
        );
    }

    /**
     * Section 6.1 step 11, M-1, SAML Bindings §3.4.4.1: a SAMLResponse given to logoutMessage() is the model's
     * unverified LogoutResponse, its Issuer and InResponseTo read.
     */
    #[Test]
    public function itReceivesALogoutResponse(): void
    {
        // When
        $received = self::receiver()
            ->logoutMessage(
                RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))->toString(),
            );

        // Then
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);
        static::assertSame(
            ['https://sp.example.com/saml', self::LOGOUT_REQUEST_ID, Binding::HttpRedirect],
            [$received->response->issuer, $received->response->inResponseTo, $received->binding],
        );
    }

    /**
     * §9.3 row 5, B-9, section 8, SAML Bindings §3.4.3: RelayState is returned as decoded, at the 80 bytes of the
     * binding and at exactly 1 024 bytes, the exception of section 8, and null when the query string has none.
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itReturnsRelayStateAsDecoded(RedirectQuery $query, ?string $relayState): void
    {
        // When
        $received = self::receiver()->authnRequest($query->toString());

        // Then
        static::assertSame($relayState, $received->relayState);
    }

    /**
     * @return iterable<string, array{RedirectQuery, ?string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield 'none' => [self::authnRequestQuery(), null];
        yield 'exactly 80 bytes' => [
            self::authnRequestQuery()->withRelayState(str_repeat('€', 26) . 'ab'),
            str_repeat('€', 26) . 'ab',
        ];
        yield 'exactly 1 024 bytes' => [
            self::authnRequestQuery()->withRelayState(str_repeat('€', 341) . 'a'),
            str_repeat('€', 341) . 'a',
        ];
    }

    /**
     * §9.3 row 1, B-2, SAML Bindings §3.4.4.1: parameters that arrive as SigAlg, Signature, RelayState, SAMLRequest,
     * signed in the order of the binding, are accepted, whatever the order of arrival.
     */
    #[Test]
    public function itVerifiesTheOctetsWhateverTheOrderOfArrival(): void
    {
        // Given
        $query = self::authnRequestQuery()
            ->withRelayState('state')
            ->signed()
            ->inOrder(['SigAlg', 'Signature', 'RelayState', 'SAMLRequest']);

        // When
        $accepted = self::receiver()
            ->authnRequest($query->toString())
            ->validate(self::authnRequestValidator(), self::serviceProvider(), self::identityProvider(), self::SSO);

        // Then
        static::assertSame(Authentication::Binding, $accepted->authentication);
    }

    /**
     * §9.3 row 2, B-2, B-8, SAML Bindings §3.4.4.1: values escaped in lowercase hexadecimal, a space of RelayState
     * written + or %20, signed as they were sent, are accepted, and RelayState is decoded to the same string either
     * way.
     */
    #[Test]
    #[DataProvider('provideSpacesOfRelayState')]
    public function itVerifiesTheOctetsAsTheyWereSent(string $relayState): void
    {
        // Given
        $query = RedirectQuery::none()
            ->with('SAMLRequest', RedirectQuery::inLowercase(self::authnRequestQuery()->value('SAMLRequest')))
            ->with('RelayState', $relayState)
            ->with('SigAlg', RedirectQuery::encodeInLowercase(SignatureAlgorithm::RsaSha256->value));
        $query = $query->signedOver($query->octets());
        $received = self::receiver()->authnRequest($query->toString());

        // When
        $accepted = $received->validate(
            self::authnRequestValidator(),
            self::serviceProvider(),
            self::identityProvider(),
            self::SSO,
        );

        // Then
        static::assertSame([Authentication::Binding, 'a state/1'], [$accepted->authentication, $received->relayState]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSpacesOfRelayState(): iterable
    {
        yield 'a space written +' => ['a+state%2f1'];
        yield 'a space written %20' => ['a%20state%2f1'];
    }

    /**
     * §9.3 row 3, §9.3 row 4, §9.3 row 6, §9.3 row 10, B-1, B-2, SAML Bindings §3.4.4.1: the query of a Location,
     * other parameters, a trailing &, empty segments and SAMLEncoding of DEFLATE are skipped and never signed: the
     * octets of B-2 verify without them.
     */
    #[Test]
    #[DataProvider('provideQueriesWithWhatIsNotSigned')]
    public function itSignsNeitherOtherParametersNorSamlEncoding(string $queryString): void
    {
        // When
        $accepted = self::receiver()
            ->authnRequest($queryString)
            ->validate(self::authnRequestValidator(), self::serviceProvider(), self::identityProvider(), self::SSO);

        // Then
        static::assertSame(Authentication::Binding, $accepted->authentication);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueriesWithWhatIsNotSigned(): iterable
    {
        $signed = self::authnRequestQuery()->withRelayState('state')->signed()->toString();

        yield 'the query of a Location, ?tenant=acme' => ['tenant=acme&' . $signed];
        yield 'parameters other than the six, between them' => [str_replace(
            '&SigAlg',
            '&lang=fr&x=%41&SigAlg',
            $signed,
        )];
        yield 'a trailing &' => [$signed . '&'];
        yield 'empty segments' => ['&&' . str_replace('&RelayState', '&&RelayState', $signed)];
        yield 'SAMLEncoding of DEFLATE' => [
            $signed . '&SAMLEncoding=urn%3Aoasis%3Anames%3Atc%3ASAML%3A2.0%3Abindings%3AURL-Encoding%3ADEFLATE',
        ];
    }

    /**
     * §9.2 row 3, B-1, SAML Bindings §3.4.4.1: a query string without SAMLRequest or SAMLResponse is refused.
     */
    #[Test]
    #[DataProvider('provideQueriesWithoutMessage')]
    public function itRefusesAQueryStringWithoutMessage(string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The query string carries neither SAMLRequest nor SAMLResponse (B-1).');

        // When
        self::receiver()->logoutMessage($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueriesWithoutMessage(): iterable
    {
        yield 'an empty query string' => [''];
        yield 'RelayState alone' => ['RelayState=state'];
        yield 'the signature without the message' => [self::authnRequestQuery()
            ->signed()
            ->without('SAMLRequest')
            ->toString()];
    }

    /**
     * §9.2 row 4, B-1, section 6.1 step 3, SAML Bindings §3.4.4.1: a SAMLResponse given to authnRequest() is refused.
     */
    #[Test]
    public function itRefusesASamlResponseGivenToAuthnRequest(): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('The query string carries a message parameter the method does not take (B-1).');

        // When
        self::receiver()
            ->authnRequest(RedirectQuery::carrying('SAMLResponse', self::fixture(self::AUTHN_REQUEST))->toString());
    }

    /**
     * §9.2 row 5, B-1, SAML Bindings §3.4.4.1: a second SAMLRequest, SAMLResponse, RelayState, SigAlg, Signature or
     * SAMLEncoding is refused, before the first and after it.
     */
    #[Test]
    #[DataProvider('provideSecondParameters')]
    public function itRefusesAParameterTwice(string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('A parameter of the binding appears more than once (B-1).');

        // When
        self::receiver()->logoutMessage($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSecondParameters(): iterable
    {
        $request = RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST))
            ->withRelayState('state')
            ->signed('idp')
            ->with('SAMLEncoding', RedirectQuery::encode('urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE'));
        $response = RedirectQuery::carrying('SAMLResponse', self::fixture(self::LOGOUT_RESPONSE))->signed();
        $queries = [
            'SAMLRequest' => $request,
            'SAMLResponse' => $response,
            'RelayState' => $request,
            'SigAlg' => $request,
            'Signature' => $request,
            'SAMLEncoding' => $request,
        ];
        foreach ($queries as $name => $query) {
            $second = $name . '=' . $query->value($name);

            yield 'a second ' . $name . ' before the first' => [$second . '&' . $query->toString()];
            yield 'a second ' . $name . ' after the first' => [$query->toString() . '&' . $second];
        }
    }

    /**
     * §9.2 row 6, B-1, section 6.1 step 2, SAML Bindings §3.4.4.1: a parameter of B-1 under a name PHP's parser of a
     * query string reads as it while it is not written so, percent-encoded, after a leading space, followed by a NUL
     * or a "[", is refused, alone and next to the literal one.
     */
    #[Test]
    #[DataProvider('provideNamesReadAsAParameterOfTheBinding')]
    public function itRefusesANameReadAsAParameterOfTheBinding(string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('A name reads as a parameter of the binding once percent-decoded, its leading spaces dropped or cut at a NUL or a "[" (B-1).');

        // When
        self::receiver()->authnRequest($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesReadAsAParameterOfTheBinding(): iterable
    {
        $query = self::authnRequestQuery()->withRelayState('state')->signed();
        $message = $query->value('SAMLRequest');

        yield 'SAML%52equest alone' => ['SAML%52equest=' . $message];
        yield 'SAML%52equest next to SAMLRequest' => [$query->toString() . '&SAML%52equest=' . $message];
        yield 'SAML%52equest before SAMLRequest' => ['SAML%52equest=' . $message . '&' . $query->toString()];
        yield 'Sig%41lg alone' => [$query->without('SigAlg')->toString() . '&Sig%41lg=' . $query->value('SigAlg')];
        yield 'Sig%41lg next to SigAlg' => [$query->toString() . '&Sig%41lg=' . $query->value('SigAlg')];
        yield 'Relay%53tate alone' => [$query->without('RelayState')->toString() . '&Relay%53tate=state'];
        yield 'Relay%53tate next to RelayState' => [$query->toString() . '&Relay%53tate=other'];
        yield 'in lowercase hexadecimal, Sig%6eature' => [$query->toString() . '&Sig%6eature=x'];
        yield 'the whole name escaped, without =' => [$query->toString() . '&%53%41%4D%4C%45%6E%63%6F%64%69%6E%67'];
        yield 'a space written + before SAMLRequest, alone' => ['+SAMLRequest=' . $message];
        yield 'a space written + before SAMLRequest, next to it' => [$query->toString() . '&+SAMLRequest=' . $message];
        yield 'a space written %20 before SigAlg, next to it' => [$query->toString() . '&%20SigAlg=x'];
        yield 'two raw spaces before RelayState, alone' => [
            $query->without('RelayState')->toString() . '&  RelayState=x',
        ];
        yield 'a NUL after SAMLRequest, alone' => ['SAMLRequest%00=' . $message];
        yield 'a NUL and a letter after SAMLResponse, next to SAMLRequest' => [
            $query->toString() . '&SAMLResponse%00x=y',
        ];
        yield 'a NUL after Signature, before it' => ['Signature%00=x&' . $query->toString()];
        yield 'brackets after SAMLRequest, alone' => ['SAMLRequest[]=' . $message];
        yield 'escaped brackets after SAMLRequest, next to it' => [
            $query->toString() . '&SAMLRequest%5B%5D=' . $message,
        ];
        yield 'an index after RelayState, next to it' => [$query->toString() . '&RelayState[0]=other'];
        yield 'an unclosed bracket after SAMLEncoding' => [$query->toString() . '&SAMLEncoding[=x'];
        yield 'a leading space, an escape, a NUL and an index together' => [$query->toString() . '&+Sig%41lg%00[x]=y'];
    }

    /**
     * §9.2 row 7, B-1, SAML Bindings §3.4.4.1: a parameter of B-1 without = is refused.
     */
    #[Test]
    #[DataProvider('provideParametersWithoutEquals')]
    public function itRefusesAParameterWithoutEquals(string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('A parameter of the binding has no "=" (B-1).');

        // When
        self::receiver()->logoutMessage($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideParametersWithoutEquals(): iterable
    {
        $query = RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST))->signed('idp')->toString();

        yield 'SAMLRequest alone' => ['SAMLRequest'];
        foreach (['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature', 'SAMLEncoding'] as $name) {
            yield $name . ' after the parameters' => [$query . '&' . $name];
        }
    }

    /**
     * §9.2 row 7, B-8, section 6.1 step 3, SAML Bindings §3.4.4.1: an empty SAMLRequest or SAMLResponse is refused
     * before anything else reads the query string.
     */
    #[Test]
    #[DataProvider('provideEmptyMessages')]
    public function itRefusesAnEmptyMessage(string $queryString): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('The message parameter is empty (B-8).');

        // When
        self::receiver()->logoutMessage($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEmptyMessages(): iterable
    {
        yield 'an empty SAMLRequest' => ['SAMLRequest='];
        yield 'an empty SAMLResponse' => ['SAMLResponse='];
        yield 'an empty SAMLRequest, SigAlg off the list' => ['SAMLRequest=&SigAlg=x&Signature=x'];
    }

    /**
     * §9.2 row 7, B-8, SAML Bindings §3.4.4.1: an empty Signature is refused.
     */
    #[Test]
    public function itRefusesAnEmptySignature(): void
    {
        // Given
        $query = self::authnRequestQuery()->signed()->replaced('Signature', '');

        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is empty (B-8).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * §9.2 row 9, B-3, SAML Bindings §3.4.4.1: a Signature without SigAlg, or a SigAlg without Signature, is refused.
     */
    #[Test]
    #[DataProvider('provideHalfSignatures')]
    public function itRefusesHalfASignature(string $queryString): void
    {
        // Then
        $this->expectException(MalformedParameters::class);
        $this->expectExceptionMessageIs('SigAlg and Signature are both present or both absent (B-3).');

        // When
        self::receiver()->authnRequest($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHalfSignatures(): iterable
    {
        $query = self::authnRequestQuery()->withRelayState('state')->signed();

        yield 'a Signature without SigAlg' => [$query->without('SigAlg')->toString()];
        yield 'a SigAlg without Signature' => [$query->without('Signature')->toString()];
    }

    /**
     * §9.2 row 10, B-3, D-5, section 6.1 step 5: a SigAlg off the closed list, RSA-SHA1 and DSA-SHA1 although SAML
     * Bindings §3.4.4.1 requires them, is refused before the message is decoded: the message, a DEFLATE bomb of 5 MiB
     * that would exceed maxInflatedBytes, is never inflated.
     */
    #[Test]
    #[DataProvider('provideAlgorithmsOffTheList')]
    public function itRefusesAnAlgorithmOffTheListBeforeInflating(string $sigAlg): void
    {
        // Given
        $query = RedirectQuery::none()
            ->with('SAMLRequest', RedirectQuery::encode(base64_encode($this->zeros(5 * 1_048_576))))
            ->with('SigAlg', RedirectQuery::encode($sigAlg))
            ->with('Signature', RedirectQuery::encode(base64_encode(str_repeat("\x01", 256))));

        // Then
        $this->expectException(UnknownSignatureAlgorithm::class);
        $this->expectExceptionMessageIs('The signature algorithm is not one of the six RSA schemes the namespace verifies (D-5).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAlgorithmsOffTheList(): iterable
    {
        yield 'RSA-SHA1' => ['http://www.w3.org/2000/09/xmldsig#rsa-sha1'];
        yield 'DSA-SHA1' => ['http://www.w3.org/2000/09/xmldsig#dsa-sha1'];
        yield 'ECDSA-SHA256' => ['http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'];
        yield 'HMAC-SHA256' => ['http://www.w3.org/2001/04/xmldsig-more#hmac-sha256'];
        yield 'an unknown URI' => ['urn:example:signature'];
        yield 'an empty value' => [''];
    }

    /**
     * §9.2 row 16, B-9, section 8, SAML Bindings §3.4.3: a RelayState of 1 025 bytes once decoded, one over the
     * exception section 8 makes to the binding, is refused.
     */
    #[Test]
    #[DataProvider('provideRelayStatesOf1025Bytes')]
    public function itRefusesARelayStateOf1025Bytes(string $relayState): void
    {
        // Given
        $query = self::authnRequestQuery()->withRelayState($relayState)->signed();

        // Then
        $this->expectException(InvalidRelayState::class);
        $this->expectExceptionMessageIs('The RelayState is longer than 1024 bytes (B-9).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRelayStatesOf1025Bytes(): iterable
    {
        yield '1 025 characters of one byte' => [str_repeat('a', 1_025)];
        yield '341 characters of three bytes and two of one' => [str_repeat('€', 341) . 'ab'];
    }

    /**
     * §9.2 row 16, B-9, section 12, SAML Bindings §3.4.3: an empty RelayState is refused, absence saying the same.
     */
    #[Test]
    public function itRefusesAnEmptyRelayState(): void
    {
        // Given
        $query = self::authnRequestQuery()->with('RelayState', '')->signed();

        // Then
        $this->expectException(InvalidRelayState::class);
        $this->expectExceptionMessageIs('The RelayState is empty (B-9).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * §9.2 row 19, section 7, SAML Bindings §3.4.4.1: the text of Signature longer than 1 368 characters, the base64 of
     * 1 027 bytes, is refused before it is decoded.
     */
    #[Test]
    public function itRefusesASignatureTextLongerThan1368Characters(): void
    {
        // Given
        $query = self::authnRequestQuery()
            ->withSigAlg(SignatureAlgorithm::RsaSha256)
            ->with('Signature', RedirectQuery::encode(base64_encode(str_repeat("\x01", 1_027))));

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The text of Signature is longer than 1368 characters (section 7).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * §9.2 row 21, B-6, SAML Bindings §3.4.4.1 step 1: a message whose root holds a ds:Signature is refused, whether
     * the query string is signed or not.
     */
    #[Test]
    #[DataProvider('provideXmlSignedMessages')]
    public function itRefusesAnXmlSignature(RedirectQuery $query): void
    {
        // Then
        $this->expectException(XmlSignatureRefused::class);
        $this->expectExceptionMessageIs('The message received over HTTP-Redirect holds a ds:Signature, which the binding removes (B-6).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * @return iterable<string, array{RedirectQuery}>
     */
    public static function provideXmlSignedMessages(): iterable
    {
        $query = RedirectQuery::carrying(
            'SAMLRequest',
            self::fixture('hostile/authn-request-xml-signature-over-http-redirect-refused.xml'),
        );

        yield 'the query string signed' => [$query->signed()];
        yield 'the query string unsigned' => [$query];
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8, SAML Bindings §3.4.4.1: the largest DEFLATE bomb a query string under
     * maxQueryStringBytes carries, 6 MiB of zeros deflated by zlib at level 9 into 6 113 bytes, a query string of 8 168
     * bytes (the largest measured on 1 October 2026, zlib 1.3.1, is 6 311 474 bytes into 8 190), is refused at
     * maxInflatedBytes.
     */
    #[Test]
    public function itRefusesTheLargestBombAQueryStringCarries(): void
    {
        // Given
        $query = $this->largestBomb();

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 65536 bytes (B-7).');

        // When
        self::receiver()->authnRequest($query);
    }

    /**
     * §9.2 row 22, B-7, section 6.1 step 8, SAML Bindings §3.4.4.1: what the largest bomb costs the receiver before its
     * refusal is the bound, plus the output of one byte of input, at most 1 032 bytes, plus zlib's fixed state, 64 KiB
     * its window among it, as the inflater alone (InflaterTest), plus the query string held in its decodings: its
     * segments, its value percent-decoded then base64-decoded, each no longer than the query string. Measured on 1
     * October 2026, zlib 1.3.1, the same on PHP 8.5.10 and 8.4.25, Xdebug collecting coverage or not: a peak of 135 904
     * to 135 984 bytes under the default bound, the ceiling asserted 156 608, where the bomb inflated whole would hold
     * 6 291 456.
     */
    #[Test]
    public function itHoldsTheLargestBombWithinTheBound(): void
    {
        // Given
        $query = $this->largestBomb();
        $receiver = self::receiver();
        $this->receiveAndForget($receiver, $query);
        $before = memory_get_usage();
        memory_reset_peak_usage();

        // When
        $this->receiveAndForget($receiver, $query);

        // Then
        static::assertLessThan(65_536 + 1_032 + 65_536 + (3 * strlen($query)), memory_get_peak_usage() - $before);
    }

    /**
     * §9.2 row 22, B-7, SAML Bindings §3.4.4.1: a message one byte over maxInflatedBytes is refused, the bound named.
     */
    #[Test]
    public function itRefusesAMessageOneByteOverMaxInflatedBytes(): void
    {
        // Given
        $message = self::fixture(self::AUTHN_REQUEST);
        $receiver = new RedirectReceiver(
            SamlLoader::create(),
            new BindingLimits(maxInflatedBytes: strlen($message) - 1),
        );

        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The inflated message is longer than maxInflatedBytes, 507 bytes (B-7).');

        // When
        $receiver->authnRequest(self::authnRequestQuery()->toString());
    }

    /**
     * B-7, section 7, SAML Bindings §3.4.4.1: a message of exactly maxInflatedBytes is accepted.
     */
    #[Test]
    public function itAcceptsAMessageOfExactlyMaxInflatedBytes(): void
    {
        // Given
        $message = self::fixture(self::AUTHN_REQUEST);
        $receiver = new RedirectReceiver(SamlLoader::create(), new BindingLimits(maxInflatedBytes: strlen($message)));

        // When
        $received = $receiver->authnRequest(self::authnRequestQuery()->toString());

        // Then
        static::assertSame('https://sp.example.com/saml', $received->request->issuer);
    }

    /**
     * §9.2 row 23, B-7, section 6.1 step 1, SAML Bindings §3.4.4: a query string over maxQueryStringBytes is refused
     * before anything reads it, a malformed one among them.
     */
    #[Test]
    #[DataProvider('provideQueriesOverTheBound')]
    public function itRefusesAQueryStringOverMaxQueryStringBytes(string $queryString): void
    {
        // Then
        $this->expectException(LimitExceeded::class);
        $this->expectExceptionMessageIs('The query string is longer than maxQueryStringBytes, 8192 bytes (B-7).');

        // When
        self::receiver()->authnRequest($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideQueriesOverTheBound(): iterable
    {
        $query = self::authnRequestQuery()->withRelayState('state')->signed()->toString() . '&pad=';

        yield 'a signed query string of 8 193 bytes' => [$query . str_repeat('x', 8_193 - strlen($query))];
        yield 'both message parameters, 8 193 bytes' => ['SAMLRequest=a&SAMLResponse=' . str_repeat('x', 8_166)];
    }

    /**
     * B-7, section 7, SAML Bindings §3.4.4: a query string of exactly maxQueryStringBytes is accepted.
     */
    #[Test]
    public function itAcceptsAQueryStringOfExactlyMaxQueryStringBytes(): void
    {
        // Given
        $query = self::authnRequestQuery()->toString();
        $receiver = new RedirectReceiver(SamlLoader::create(), new BindingLimits(maxQueryStringBytes: strlen($query)));

        // When
        $received = $receiver->authnRequest($query);

        // Then
        static::assertSame('https://sp.example.com/saml', $received->request->issuer);
    }

    /**
     * §9.2 row 24, B-8, RFC 1950, RFC 1951, RFC 1952: a message wrapped by zlib or gzip, cut before its final block,
     * followed by a byte, or not DEFLATE, is refused.
     */
    #[Test]
    #[DataProvider('provideStreamsThatAreNotRawDeflate')]
    public function itRefusesWhatIsNotRawDeflate(string $stream, string $message): void
    {
        // Given
        $query = RedirectQuery::none()->with('SAMLRequest', RedirectQuery::encode(base64_encode($stream)));

        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs($message);

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStreamsThatAreNotRawDeflate(): iterable
    {
        $xml = self::fixture(self::AUTHN_REQUEST);
        $raw = self::deflated($xml);

        yield 'wrapped by zlib, RFC 1950' => [self::bytes(gzcompress($xml)), 'The message is not raw DEFLATE (B-8).'];
        yield 'wrapped by gzip, RFC 1952' => [self::bytes(gzencode($xml)), 'The message is not raw DEFLATE (B-8).'];
        yield 'the message itself, not deflated' => [$xml, 'The message is not raw DEFLATE (B-8).'];
        yield 'cut before its final block' => [
            substr($raw, 0, -1),
            'The DEFLATE stream ends before its final block (B-8).',
        ];
        yield 'a byte after its final block' => [
            $raw . "\0",
            'Bytes follow the final block of the DEFLATE stream (B-8).',
        ];
    }

    /**
     * §9.2 row 25, §9.2 row 26, B-8, RFC 4648 §3.5, §4, SAML Bindings §3.4.4.1: the base64 of the message in any form
     * but its one form, or with whitespace, a + left unescaped and decoded to a space among it, is refused.
     */
    #[Test]
    #[DataProvider('provideMessagesNotInTheirOneBase64')]
    public function itRefusesAMessageNotInItsOneBase64(string $raw): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).');

        // When
        self::receiver()->authnRequest('SAMLRequest=' . $raw);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMessagesNotInTheirOneBase64(): iterable
    {
        $base64 = base64_encode(self::deflated(self::fixture(self::AUTHN_REQUEST)));

        yield 'an unused bit set' => [RedirectQuery::encode(self::withAnUnusedBitSet($base64))];
        yield 'a = missing' => [RedirectQuery::encode(substr($base64, 0, -1))];
        yield 'an extra =' => [RedirectQuery::encode($base64 . '=')];
        yield 'the URL-safe alphabet' => [RedirectQuery::encode(str_replace(['+', '/'], ['-', '_'], $base64))];
        yield 'a character outside the alphabet' => [RedirectQuery::encode('*' . $base64)];
        yield 'a space, written %20' => [RedirectQuery::encode(substr_replace($base64, ' ', 8, 0))];
        yield 'a line feed, written %0A' => [RedirectQuery::encode(substr_replace($base64, "\n", 76, 0))];
        yield 'a + left unescaped, decoded to a space' => [str_replace('%2B', '+', RedirectQuery::encode($base64))];
    }

    /**
     * §9.2 row 26, B-8, SAML Bindings §3.4.4.1: a + left unescaped in the base64 of Signature, decoded to a space, is
     * refused.
     */
    #[Test]
    public function itRefusesAPlusLeftUnescapedInTheSignature(): void
    {
        // Given
        $query = self::authnRequestQuery()
            ->withSigAlg(SignatureAlgorithm::RsaSha256)
            ->with('Signature', base64_encode(str_repeat("\xFB\xEF\xBE", 86)));

        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A base64 value is not in its one form: the alphabet and the padding of RFC 4648 section 4, the unused bits zero, no whitespace (B-8).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    /**
     * §9.2 row 27, B-8, SAML Bindings §3.4.4.1: a percent-escape %G1, %2 or a trailing %, in a name and in a value, is
     * refused.
     */
    #[Test]
    #[DataProvider('provideMalformedEscapes')]
    public function itRefusesAMalformedPercentEscape(string $queryString): void
    {
        // Then
        $this->expectException(MalformedEncoding::class);
        $this->expectExceptionMessageIs('A percent-escape is not a % followed by two hexadecimal digits (B-8).');

        // When
        self::receiver()->authnRequest($queryString);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedEscapes(): iterable
    {
        $query = self::authnRequestQuery()->withRelayState('state')->signed();
        $signed = $query->toString();

        yield '%G1 in the name of a parameter of the binding' => [$signed . '&Relay%G1State=x'];
        yield '%2 in the name of another parameter' => ['tenant%2=acme&' . $signed];
        yield 'a trailing % in a name' => [$signed . '&tenant%=acme'];
        yield '%G1 in the message' => [$query
            ->replaced('SAMLRequest', $query->value('SAMLRequest') . '%G1')
            ->toString()];
        yield '%2 in RelayState' => [$query->replaced('RelayState', 'state%2')->toString()];
        yield 'a trailing % in SigAlg' => [$query->replaced('SigAlg', $query->value('SigAlg') . '%')->toString()];
        yield '%G1 in Signature' => [$query->replaced('Signature', '%G1' . $query->value('Signature'))->toString()];
        yield 'a trailing % in SAMLEncoding' => [$signed . '&SAMLEncoding=%'];
    }

    /**
     * §9.2 row 28, section 8, SAML Bindings §3.4.4: a SAMLEncoding of another URI is refused by name.
     */
    #[Test]
    #[DataProvider('provideOtherEncodings')]
    public function itRefusesAnotherEncoding(string $encoding): void
    {
        // Then
        $this->expectException(Unsupported::class);
        $this->expectExceptionMessageIs('A SAMLEncoding other than DEFLATE is refused (section 8).');

        // When
        self::receiver()->authnRequest(self::authnRequestQuery()->with('SAMLEncoding', $encoding)->toString());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherEncodings(): iterable
    {
        yield 'another URI' => [RedirectQuery::encode('urn:example:encoding')];
        yield 'DEFLATE in lower case' =>
            [RedirectQuery::encode('urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:deflate')];
        yield 'empty' => [''];
    }

    /**
     * §9.2 row 31, section 6.1 step 11, M-1, SAML Bindings §3.4.4: a message of another root than the method and the
     * parameter expect is the model's MalformedMessage.
     *
     * @param 'authnRequest'|'logoutMessage' $method
     */
    #[Test]
    #[DataProvider('provideMessagesOfAnotherRoot')]
    public function itRefusesAMessageOfAnotherRoot(string $method, RedirectQuery $query, string $message): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->receive($method, $query->toString());
    }

    /**
     * @return iterable<string, array{'authnRequest'|'logoutMessage', RedirectQuery, string}>
     */
    public static function provideMessagesOfAnotherRoot(): iterable
    {
        yield 'a samlp:Response given to logoutMessage()' => [
            'logoutMessage',
            RedirectQuery::carrying('SAMLResponse', self::fixture('hostile/response-over-http-redirect-refused.xml')),
            'The root of the message is not a samlp:LogoutResponse (section 5.4).',
        ];
        yield 'an AuthnRequest in a SAMLResponse' => [
            'logoutMessage',
            RedirectQuery::carrying('SAMLResponse', self::fixture(self::AUTHN_REQUEST)),
            'The root of the message is not a samlp:LogoutResponse (section 5.4).',
        ];
        yield 'a LogoutResponse in a SAMLRequest' => [
            'logoutMessage',
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_RESPONSE)),
            'The root of the message is not a samlp:LogoutRequest (section 5.4).',
        ];
        yield 'a LogoutRequest given to authnRequest()' => [
            'authnRequest',
            RedirectQuery::carrying('SAMLRequest', self::fixture(self::LOGOUT_REQUEST)),
            'The root of the document is not a samlp:AuthnRequest (section 6.2).',
        ];
    }

    /**
     * §9.2 row 32, B-10, I-1, SAML Bindings §3.4.4.1: a DOCTYPE among the inflated bytes is Core's refusal, as it is.
     */
    #[Test]
    public function itLetsCoreRefuseADoctype(): void
    {
        // Given
        $query = RedirectQuery::carrying('SAMLRequest', self::fixture('hostile/authn-request-doctype-refused.xml'));

        // Then
        $this->expectException(DoctypeRefused::class);
        $this->expectExceptionMessageIs('The input contains a document type declaration (I-1).');

        // When
        self::receiver()->authnRequest($query->toString());
    }

    private static function authnRequestQuery(): RedirectQuery
    {
        return RedirectQuery::carrying('SAMLRequest', self::fixture(self::AUTHN_REQUEST));
    }

    /**
     * @param 'authnRequest'|'logoutMessage' $method
     */
    private function receive(
        string $method,
        string $queryString,
    ): ReceivedAuthnRequest|ReceivedLogoutRequest|ReceivedLogoutResponse {
        return match ($method) {
            'authnRequest' => self::receiver()->authnRequest($queryString),
            'logoutMessage' => self::receiver()->logoutMessage($queryString),
        };
    }

    /**
     * The query string of §9.2 row 22: 6 MiB of zeros, deflated at level 9, as the message of a query string.
     */
    private function largestBomb(): string
    {
        $query = 'SAMLRequest=' . RedirectQuery::encode(base64_encode($this->zeros(6 * 1_048_576)));
        static::assertLessThanOrEqual(8_192, strlen($query));

        return $query;
    }

    /**
     * $query received, its refusal for exceeding maxInflatedBytes swallowed: what is measured is the state it leaves.
     */
    private function receiveAndForget(RedirectReceiver $receiver, string $query): void
    {
        try {
            $receiver->authnRequest($query);
        } catch (LimitExceeded) {
        }
    }

    /**
     * $length zeros, raw-deflated at level 9.
     */
    private function zeros(int $length): string
    {
        return self::bytes(gzdeflate(str_repeat("\0", $length), 9, ZLIB_ENCODING_RAW));
    }

    private static function deflated(string $bytes): string
    {
        return self::bytes(gzdeflate($bytes, -1, ZLIB_ENCODING_RAW));
    }

    /**
     * What a function of zlib returned, a failure stopping the test.
     */
    private static function bytes(string|false $bytes): string
    {
        if (! is_string($bytes)) {
            throw new LogicException('zlib failed on a fixture.');
        }

        return $bytes;
    }

    /**
     * $base64, padded, with the lowest of the unused bits of its last character set (RFC 4648 §3.5).
     */
    private static function withAnUnusedBitSet(string $base64): string
    {
        $data = rtrim($base64, '=');
        $index = strpos(self::BASE64, $data[strlen($data) - 1]);
        if (! is_int($index) || $data === $base64) {
            throw new LogicException('The base64 of the fixture has no unused bit.');
        }

        return substr($data, 0, -1) . self::BASE64[$index | 1] . substr($base64, strlen($data));
    }
}
