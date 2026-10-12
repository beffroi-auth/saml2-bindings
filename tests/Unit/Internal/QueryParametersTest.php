<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use function array_key_first;
use function base64_encode;
use Beffroi\Saml2\Bindings\Internal\DetachedSignature;
use Beffroi\Saml2\Bindings\Internal\QueryParameters;
use Beffroi\Saml2\Bindings\Tests\Support\RedirectQuery;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function in_array;
use function parse_str;
use function str_repeat;
use function strlen;

/**
 * Section 6.1 steps 2 to 7, B-1, B-2, B-3, B-9: what the reading of a query string returns, the message parameter and
 * its raw value, RelayState decoded, the detached signature with its algorithm, its decoded value and its octets. What
 * it refuses is asserted through RedirectReceiver, row by row of section 9.2 (RedirectReceiverTest).
 */
final class QueryParametersTest extends TestCase
{
    private const string SIG_ALG = 'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';

    /**
     * B-1, B-2, SAML Bindings §3.4.4.1: the message parameter and its value exactly as it arrived, still
     * percent-encoded, in either case.
     */
    #[Test]
    public function itKeepsTheMessageAsItArrived(): void
    {
        // When
        $parameters = $this->read('SAMLRequest=fZDB%2bq0%3D', ['SAMLRequest']);

        // Then
        static::assertSame(['SAMLRequest', 'fZDB%2bq0%3D'], [$parameters->messageParameter, $parameters->message]);
    }

    /**
     * Section 6.1 step 3, SAML Bindings §3.4.4.1: a SAMLResponse, where the method takes one.
     */
    #[Test]
    public function itReadsASamlResponseWhereTheMethodTakesOne(): void
    {
        // When
        $parameters = $this->read('SAMLResponse=fZDB', ['SAMLRequest', 'SAMLResponse']);

        // Then
        static::assertSame(['SAMLResponse', 'fZDB'], [$parameters->messageParameter, $parameters->message]);
    }

    /**
     * §9.3 row 5, B-3, B-9, SAML Bindings §3.4.4.1: a query string without SigAlg and Signature has no detached
     * signature, and without RelayState no RelayState.
     */
    #[Test]
    public function itReadsAnUnsignedQueryString(): void
    {
        // When
        $parameters = $this->read('SAMLRequest=fZDB', ['SAMLRequest']);

        // Then
        static::assertSame([null, null], [$parameters->relayState, $parameters->signature]);
    }

    /**
     * §9.3 row 10, B-1, SAML Bindings §3.4.4.1: what is not one of the six parameters is skipped, whatever its name
     * once decoded, as an empty segment is.
     */
    #[Test]
    #[DataProvider('provideOtherSegments')]
    public function itSkipsWhatTheBindingDoesNotRead(string $queryString): void
    {
        // When
        $parameters = $this->read($queryString, ['SAMLRequest']);

        // Then
        static::assertSame(['fZDB', null, null], [
            $parameters->message,
            $parameters->relayState,
            $parameters->signature,
        ]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideOtherSegments(): iterable
    {
        yield 'the query of a Location, before' => ['tenant=acme&SAMLRequest=fZDB'];
        yield 'the query of a Location, after' => ['SAMLRequest=fZDB&tenant=acme'];
        yield 'a trailing &' => ['SAMLRequest=fZDB&'];
        yield 'a leading & and an empty segment' => ['&SAMLRequest=fZDB&&'];
        yield 'a segment of an empty name' => ['=x&SAMLRequest=fZDB'];
        yield 'a parameter without =' => ['debug&SAMLRequest=fZDB'];
        yield 'a parameter named in another case' => ['samlrequest=x&SAMLRequest=fZDB'];
        yield 'a percent-encoded name of another parameter' => ['t%65nant=acme&SAMLRequest=fZDB'];
        yield 'a ; inside the value of another parameter' => ['tenant=a;SAMLRequest=x&SAMLRequest=fZDB'];
        yield 'a name PHP\'s parser reads with a tab before it' => ['%09SAMLRequest=x&SAMLRequest=fZDB'];
        yield 'a name PHP\'s parser reads with an underscore after it' => [
            'SAMLRequest+=x&SAMLRequest.=y&SAMLRequest=fZDB',
        ];
        yield 'a name a NUL cuts before its end' => ['SAML%00Request=x&SAMLRequest=fZDB'];
        yield 'a name a NUL begins' => ['%00SAMLRequest=x&SAMLRequest=fZDB'];
    }

    /**
     * §9.2 row 6, B-1, section 6.1 step 2: a name is read as PHP's own parser of a query string reads it, the one
     * behind $_GET, percent-decoded, its leading spaces dropped, cut at its first NUL or "[": the parameter of B-1 it
     * reads as, or null, is the one that parser reads, so that no name is one of the six for a consumer reading the
     * query string through it and none for the package.
     */
    #[Test]
    #[DataProvider('provideNames')]
    public function itReadsANameAsPhpsParserOfAQueryStringReadsIt(string $name): void
    {
        // Given
        $fields = [];
        parse_str($name . '=v', $fields);
        $read = array_key_first($fields);
        $parameters = ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature', 'SAMLEncoding'];

        // When
        $parameter = QueryParameters::parameterNamed($name);

        // Then
        static::assertSame(in_array($read, $parameters, true) ? $read : null, $parameter);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNames(): iterable
    {
        yield 'SAMLRequest as written' => ['SAMLRequest'];
        yield 'SAMLEncoding as written' => ['SAMLEncoding'];
        yield 'percent-encoded' => ['SAML%52equest'];
        yield 'percent-encoded in lowercase hexadecimal' => ['Sig%6eature'];
        yield 'a space written + before it' => ['+SAMLRequest'];
        yield 'two spaces before it' => ['+%20RelayState'];
        yield 'a raw space before it' => [' SigAlg'];
        yield 'a NUL after it' => ['SAMLResponse%00'];
        yield 'a NUL and a letter after it' => ['SAMLRequest%00x'];
        yield 'brackets after it' => ['SAMLRequest[]'];
        yield 'escaped brackets after it' => ['SAMLRequest%5B%5D'];
        yield 'an index after it' => ['RelayState[0]'];
        yield 'two indexes after it' => ['Signature[a][b]'];
        yield 'brackets and a letter after it' => ['SAMLRequest[]x'];
        yield 'a space, an escape, a NUL and an index' => ['+Sig%41lg%00[x]'];
        yield 'a tab before it' => ['%09SAMLRequest'];
        yield 'a line feed before it' => ['%0ASAMLRequest'];
        yield 'a space after it' => ['SAMLRequest+'];
        yield 'a dot after it' => ['SAMLRequest.'];
        yield 'an escaped = after it' => ['SAMLRequest%3D'];
        yield 'a closing bracket alone after it' => ['SAMLRequest]'];
        yield 'a NUL inside it' => ['SAML%00Request'];
        yield 'a NUL before it' => ['%00SAMLRequest'];
        yield 'inside brackets' => ['[SAMLRequest]'];
        yield 'in lowercase' => ['samlrequest'];
        yield 'percent-encoded twice' => ['SAML%2552equest'];
        yield 'an empty name' => [''];
        yield 'another parameter' => ['tenant'];
    }

    /**
     * §9.2 row 6, B-1, section 6.1 step 2: a "[" no "]" follows, which PHP's parser reads as "_", cuts the name all the
     * same, so that a name is one of the six for the package whenever it is for that parser, and a little more often.
     */
    #[Test]
    #[DataProvider('provideNamesWithAnUnclosedBracket')]
    public function itCutsANameAtAnUnclosedBracketToo(string $name, string $parameter): void
    {
        // When
        $read = QueryParameters::parameterNamed($name);

        // Then
        static::assertSame($parameter, $read);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideNamesWithAnUnclosedBracket(): iterable
    {
        yield 'a bracket alone' => ['SAMLRequest[', 'SAMLRequest'];
        yield 'a bracket and a letter' => ['SigAlg[x', 'SigAlg'];
        yield 'an escaped bracket' => ['RelayState%5B', 'RelayState'];
    }

    /**
     * §9.3 row 2, B-8, B-9, SAML Bindings §3.4.3: RelayState decoded under B-8, a + and a %20 a space, an escape of
     * either case its byte.
     */
    #[Test]
    #[DataProvider('provideRelayStates')]
    public function itDecodesRelayState(string $raw, string $decoded): void
    {
        // When
        $parameters = $this->read('SAMLRequest=fZDB&RelayState=' . $raw, ['SAMLRequest']);

        // Then
        static::assertSame($decoded, $parameters->relayState);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRelayStates(): iterable
    {
        yield 'a space written +' => ['a+b', 'a b'];
        yield 'a space written %20' => ['a%20b', 'a b'];
        yield 'an escape in lowercase hexadecimal' => ['a%2fb', 'a/b'];
        yield 'a ; kept in the value' => ['a;b', 'a;b'];
        yield 'one byte' => ['x', 'x'];
        yield 'exactly 80 bytes once decoded' => [str_repeat('%41', 80), str_repeat('A', 80)];
    }

    /**
     * §9.3 row 6, section 6.1 step 4, SAML Bindings §3.4.4: SAMLEncoding holding the DEFLATE URI, as it is or
     * percent-encoded.
     */
    #[Test]
    #[DataProvider('provideDeflateEncodings')]
    public function itAcceptsTheDeflateEncoding(string $raw): void
    {
        // When
        $parameters = $this->read('SAMLRequest=fZDB&SAMLEncoding=' . $raw, ['SAMLRequest']);

        // Then
        static::assertSame('fZDB', $parameters->message);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDeflateEncodings(): iterable
    {
        yield 'as it is' => [QueryParameters::DEFLATE];
        yield 'percent-encoded' => [RedirectQuery::encode(QueryParameters::DEFLATE)];
    }

    /**
     * B-3, D-5, SAML Bindings §3.4.4.1: SigAlg, percent-decoded, read on the closed list, each of its six algorithms.
     */
    #[Test]
    #[DataProvider('provideAlgorithms')]
    public function itReadsTheAlgorithm(SignatureAlgorithm $algorithm): void
    {
        // When
        $signature = $this->signature(
            'SAMLRequest=fZDB&SigAlg=' . RedirectQuery::encode($algorithm->value) . '&Signature='
                . RedirectQuery::encode(base64_encode(str_repeat("\x01", 256))),
        );

        // Then
        static::assertSame($algorithm, $signature->algorithm);
    }

    /**
     * @return iterable<string, array{SignatureAlgorithm}>
     */
    public static function provideAlgorithms(): iterable
    {
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            yield $algorithm->name => [$algorithm];
        }
    }

    /**
     * B-8, section 6.1 step 5, SAML Bindings §3.4.4.1: the value of Signature, percent-decoded then decoded as base64.
     */
    #[Test]
    public function itDecodesTheSignature(): void
    {
        // Given
        $bytes = str_repeat("\xFB\xEF\xBE\x01", 64);

        // When
        $signature = $this->signature(
            'SAMLRequest=fZDB&SigAlg=' . self::SIG_ALG . '&Signature=' . RedirectQuery::encode(base64_encode($bytes)),
        );

        // Then
        static::assertSame($bytes, $signature->signature);
    }

    /**
     * Section 7, section 6.1 step 5, SAML Bindings §3.4.4.1: the text of Signature is bounded once percent-decoded, at
     * 1 368 characters, the base64 of 1 026 bytes accepted whether it arrives as base64 writes it or escaped, three
     * times longer.
     */
    #[Test]
    #[DataProvider('provideSignatureTextsOf1368Characters')]
    public function itAcceptsASignatureTextOf1368Characters(string $raw): void
    {
        // When
        $signature = $this->signature('SAMLRequest=fZDB&SigAlg=' . self::SIG_ALG . '&Signature=' . $raw);

        // Then
        static::assertSame(1_026, strlen($signature->signature));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSignatureTextsOf1368Characters(): iterable
    {
        $text = base64_encode(str_repeat("\xFB\xEF\xBE", 342));

        yield 'as base64 writes it, with nothing to escape' => [base64_encode(str_repeat("\x01\x02\x03", 342))];
        yield 'escaped, 4 104 characters as it arrived' => [RedirectQuery::encode($text)];
    }

    /**
     * B-2, SAML Bindings §3.4.4.1: the octets of a query string whose parameters arrive in another order, escaped in
     * lowercase, next to SAMLEncoding and another parameter: the message, RelayState and SigAlg, in that order, each
     * value exactly as it arrived, and nothing else.
     */
    #[Test]
    public function itBuildsTheOctetsFromTheValuesAsTheyArrived(): void
    {
        // Given
        $sigAlg = 'http%3a%2f%2fwww.w3.org%2f2001%2f04%2fxmldsig-more%23rsa-sha256';
        $queryString =
            'tenant=acme&SigAlg='
            . $sigAlg
            . '&Signature='
            . RedirectQuery::encode(base64_encode(str_repeat("\x01", 256)))
            . '&SAMLEncoding='
            . QueryParameters::DEFLATE
            . '&RelayState=a+b%2fc&SAMLRequest=fZDB%2bq0%3d';

        // When
        $signature = $this->signature($queryString);

        // Then
        static::assertSame('SAMLRequest=fZDB%2bq0%3d&RelayState=a+b%2fc&SigAlg=' . $sigAlg, $signature->octets->bytes);
    }

    /**
     * B-2, SAML Bindings §3.4.4.1: the octets of a signed SAMLResponse name it, without RelayState when the query
     * string has none.
     */
    #[Test]
    public function itBuildsTheOctetsOfASamlResponseWithoutRelayState(): void
    {
        // Given
        $queryString =
            'SAMLResponse=fZDB&SigAlg='
            . self::SIG_ALG
            . '&Signature='
            . RedirectQuery::encode(base64_encode(str_repeat("\x01", 256)));

        // When
        $parameters = QueryParameters::read($queryString, ['SAMLRequest', 'SAMLResponse'], SamlLoader::create());

        // Then
        static::assertSame('SAMLResponse=fZDB&SigAlg=' . self::SIG_ALG, $parameters->signature?->octets->bytes);
    }

    /**
     * @param non-empty-list<'SAMLRequest'|'SAMLResponse'> $messageParameters
     */
    private function read(string $queryString, array $messageParameters): QueryParameters
    {
        return QueryParameters::read($queryString, $messageParameters, SamlLoader::create());
    }

    private function signature(string $queryString): DetachedSignature
    {
        $signature = $this->read($queryString, ['SAMLRequest'])->signature;
        static::assertInstanceOf(DetachedSignature::class, $signature);

        return $signature;
    }
}
