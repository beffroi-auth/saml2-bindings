<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Unit;

use Beffroi\Saml2\Model\Writing\AuthnRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutRequestWriter;
use Beffroi\Saml2\Model\Writing\LogoutResponseWriter;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function file_put_contents;
use function getenv;
use function is_dir;
use function mkdir;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresEnvironmentVariable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Section 9.1, B-2, B-8: the signed URLs RedirectSender writes, an AuthnRequest, a LogoutRequest and a LogoutResponse
 * under every algorithm this build has, each without RelayState and with one of 80 bytes, and an AuthnRequest to a
 * Destination holding its own query, written into the directory REDIRECT_ORACLE names, each next to the document the
 * model's writer writes for it, unsigned and serialized once: the OpenSSL command line verifies every signature over
 * the octets it builds from the URL, and Python's zlib inflates every message, which must be that document
 * (tests/Fixture/oracle/README.md, castor redirect-oracle, the job Oracle of the CI). The files are the input of the
 * oracle, not fixtures, named after the signer whose certificate verifies them: the test is skipped when the variable
 * is not set. A PSS signature is random, so nothing here is pinned.
 *
 * @phpstan-import-type Message from SendingFixtures
 */
#[RequiresEnvironmentVariable('REDIRECT_ORACLE')]
final class RedirectSenderOracleTest extends TestCase
{
    use SendingFixtures;

    /**
     * Section 9.1: a signed URL, and the document its message must inflate to, for the OpenSSL oracle.
     *
     * @param Message $message
     */
    #[Test]
    #[DataProvider('provideSignedUrls')]
    public function itWritesASignedUrlForOpenSsl(
        string $name,
        string $message,
        SignatureAlgorithm $algorithm,
        ?string $relayState,
        ?string $destination,
    ): void {
        // Given
        $url = self::send($message, $relayState, $destination, $algorithm);

        // When
        $written = [
            $this->put($name . '.url', $url),
            $this->put($name . '.xml', $this->written($message, $destination)),
        ];

        // Then
        static::assertNotContains(false, $written);
    }

    /**
     * @return iterable<string, array{string, Message, SignatureAlgorithm, ?string, ?string}>
     */
    public static function provideSignedUrls(): iterable
    {
        $signers = ['an AuthnRequest' => 'sp', 'a LogoutRequest' => 'idp', 'a LogoutResponse' => 'sp'];
        $files = [
            'an AuthnRequest' => 'authn-request',
            'a LogoutRequest' => 'logout-request',
            'a LogoutResponse' => 'logout-response',
        ];
        foreach (self::algorithms() as $algorithm) {
            foreach ($signers as $message => $signer) {
                foreach (['' => null, '-relay-state' => self::RELAY_STATE] as $suffix => $relayState) {
                    $name = sprintf('%s-%s-%s%s', $signer, $files[$message], $algorithm->name, $suffix);

                    yield $name => [$name, $message, $algorithm, $relayState, null];
                }
            }
        }
        yield 'sp-authn-request-RsaSha256-destination-query' => [
            'sp-authn-request-RsaSha256-destination-query',
            'an AuthnRequest',
            SignatureAlgorithm::RsaSha256,
            self::RELAY_STATE,
            self::SSO . '?tenant=acme',
        ];
    }

    /**
     * The document the model's writer writes for $message to $destination or to its own, unsigned, serialized once.
     *
     * @param Message $message
     */
    private function written(string $message, ?string $destination): string
    {
        return new Serializer()->serialize(match ($message) {
            'an unsigned AuthnRequest', 'an AuthnRequest' => new AuthnRequestWriter()->write(
                self::authnRequest($destination ?? self::SSO),
                null,
            ),
            'a LogoutRequest' => new LogoutRequestWriter()->write(
                self::logoutRequest($destination ?? self::SP_SLO),
                null,
            ),
            'a LogoutResponse' => new LogoutResponseWriter()->write(
                self::logoutResponse($destination ?? self::IDP_SLO),
                null,
            ),
        });
    }

    /**
     * @return int|false what file_put_contents() returns
     */
    private function put(string $name, string $bytes): int|false
    {
        $directory = getenv('REDIRECT_ORACLE');
        static::assertIsString($directory);
        static::assertTrue(is_dir($directory) || mkdir($directory, 0o777, true));

        return file_put_contents($directory . '/' . $name, $bytes);
    }
}
