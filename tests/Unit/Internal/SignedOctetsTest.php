<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit\Internal;

use Beffroi\Saml2\Bindings\Internal\SignedOctets;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * B-2, section 6.1 step 7, SAML Bindings §3.4.4.1: the octets the detached signature covers, the message parameter,
 * RelayState when present and SigAlg, in that order, each value as given, still percent-encoded.
 */
final class SignedOctetsTest extends TestCase
{
    private const string SIG_ALG = 'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';

    /**
     * B-2, SAML Bindings §3.4.4.1: the message parameter and its value, RelayState and its value when present, SigAlg
     * and its value, joined by & and nothing else.
     *
     * @param 'SAMLRequest'|'SAMLResponse' $messageParameter
     */
    #[Test]
    #[DataProvider('provideParameters')]
    public function itJoinsTheParametersInTheOrderOfTheBinding(
        string $messageParameter,
        string $message,
        ?string $relayState,
        string $expected,
    ): void {
        // When
        $octets = new SignedOctets($messageParameter, $message, $relayState, self::SIG_ALG);

        // Then
        static::assertSame($expected, $octets->bytes);
    }

    /**
     * @return iterable<string, array{'SAMLRequest'|'SAMLResponse', string, ?string, string}>
     */
    public static function provideParameters(): iterable
    {
        yield 'a SAMLRequest without RelayState' => [
            'SAMLRequest',
            'fZDB%2Bq0%3D',
            null,
            'SAMLRequest=fZDB%2Bq0%3D&SigAlg=' . self::SIG_ALG,
        ];
        yield 'a SAMLRequest with RelayState' => [
            'SAMLRequest',
            'fZDB%2Bq0%3D',
            'state%201',
            'SAMLRequest=fZDB%2Bq0%3D&RelayState=state%201&SigAlg=' . self::SIG_ALG,
        ];
        yield 'a SAMLResponse with RelayState' => [
            'SAMLResponse',
            'fZDB%2Bq0%3D',
            'state%201',
            'SAMLResponse=fZDB%2Bq0%3D&RelayState=state%201&SigAlg=' . self::SIG_ALG,
        ];
        yield 'values in lowercase hexadecimal, kept as they are' => [
            'SAMLRequest',
            'fZDB%2bq0%3d',
            'state+1',
            'SAMLRequest=fZDB%2bq0%3d&RelayState=state+1&SigAlg=' . self::SIG_ALG,
        ];
    }
}
