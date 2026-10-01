<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use function array_filter;
use function array_map;
use function array_values;
use function base64_encode;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use function gzdeflate;
use function implode;
use function is_string;
use LogicException;
use function preg_replace_callback;
use function rawurlencode;
use function sprintf;
use function strtolower;
use const ZLIB_ENCODING_RAW;

/**
 * A query string of HTTP-Redirect as the tests write it (sections 9.2 and 9.3), built from outside the package so that
 * it judges the receiver rather than mirrors it: its parameters in the order of arrival, each value exactly as it goes
 * on the wire, and a signature computed with a test key through Dsig's PrivateKey over whatever octets the test names:
 * those of SAML Bindings §3.4.4.1 by default (B-2), or any others, in any order and any escaping, for the hostile rows.
 * Nothing here calls the package: the octets are concatenated, the message deflated by zlib and encoded by PHP.
 */
final readonly class RedirectQuery
{
    /**
     * @param list<array{string, string}> $parameters each name and value as the query string carries them, in order
     */
    private function __construct(
        private array $parameters,
    ) {
    }

    /**
     * A query string with no parameter yet.
     */
    public static function none(): self
    {
        return new self([]);
    }

    /**
     * A query string carrying $xml under $name, as HTTP-Redirect encodes it (SAML Bindings §3.4.4.1).
     */
    public static function carrying(string $name, string $xml): self
    {
        return new self([[$name, self::message($xml)]]);
    }

    /**
     * $xml raw-deflated (RFC 1951), base64-encoded on one line and percent-encoded in uppercase hexadecimal, as
     * SimpleSAMLphp writes a message parameter.
     */
    public static function message(string $xml): string
    {
        $deflated = gzdeflate($xml, -1, ZLIB_ENCODING_RAW);
        if (! is_string($deflated)) {
            throw new LogicException('zlib could not deflate a message of the tests.');
        }

        return self::encode(base64_encode($deflated));
    }

    /**
     * $bytes percent-encoded as RFC 3986 writes them, every byte outside the unreserved characters as % and two
     * uppercase hexadecimal digits.
     */
    public static function encode(string $bytes): string
    {
        return rawurlencode($bytes);
    }

    /**
     * $bytes percent-encoded with lowercase hexadecimal digits, which B-8 reads as uppercase.
     */
    public static function encodeInLowercase(string $bytes): string
    {
        return self::inLowercase(rawurlencode($bytes));
    }

    /**
     * Every percent-escape of $encoded, a value already percent-encoded, in lowercase hexadecimal.
     */
    public static function inLowercase(string $encoded): string
    {
        $lowercase = preg_replace_callback(
            '~%[0-9A-F]{2}~',
            static fn (array $escape): string => strtolower($escape[0]),
            $encoded,
        );
        if (! is_string($lowercase)) {
            throw new LogicException('PCRE failed on a value of the tests.');
        }

        return $lowercase;
    }

    /**
     * $name and $value appended, $value as the query string carries it.
     */
    public function with(string $name, string $value): self
    {
        return new self([...$this->parameters, [$name, $value]]);
    }

    /**
     * RelayState appended, percent-encoded in uppercase hexadecimal.
     */
    public function withRelayState(string $relayState): self
    {
        return $this->with('RelayState', self::encode($relayState));
    }

    /**
     * SigAlg appended, the URI of $algorithm percent-encoded in uppercase hexadecimal.
     */
    public function withSigAlg(SignatureAlgorithm $algorithm): self
    {
        return $this->with('SigAlg', self::encode($algorithm->value));
    }

    /**
     * SigAlg, then Signature over the octets of B-2 the parameters then give, signed by the test key $key.
     *
     * @param 'idp'|'sp' $key
     */
    public function signed(string $key = 'sp', SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256): self
    {
        $query = $this->withSigAlg($algorithm);

        return $query->signedOver($query->octets(), $key, $algorithm);
    }

    /**
     * Signature appended, over $octets whatever they are, signed by the test key $key under $algorithm.
     *
     * @param 'idp'|'sp' $key
     */
    public function signedOver(
        string $octets,
        string $key = 'sp',
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RsaSha256,
    ): self {
        return $this->with(
            'Signature',
            self::encode(base64_encode(TestKeys::signingKey($key)->sign($octets, $algorithm))),
        );
    }

    /**
     * The octets of SAML Bindings §3.4.4.1 the parameters give as they are: the first SAMLRequest or SAMLResponse, then
     * RelayState when present, then SigAlg, each value as the query string carries it.
     */
    public function octets(): string
    {
        $message = array_values(array_filter(
            $this->parameters,
            static fn (array $parameter): bool => $parameter[0] === 'SAMLRequest' || $parameter[0] === 'SAMLResponse',
        ))[0] ?? throw new LogicException('The query string of the test carries no message parameter.');
        $relayState = $this->has('RelayState') ? '&RelayState=' . $this->value('RelayState') : '';

        return $message[0] . '=' . $message[1] . $relayState . '&SigAlg=' . $this->value('SigAlg');
    }

    /**
     * The value of the first parameter named $name, as the query string carries it.
     */
    public function value(string $name): string
    {
        foreach ($this->parameters as [$parameter, $value]) {
            if ($parameter === $name) {
                return $value;
            }
        }

        throw new LogicException(sprintf('The query string of the test has no %s.', $name));
    }

    /**
     * Every parameter named $name given $value instead.
     */
    public function replaced(string $name, string $value): self
    {
        return new self(array_map(
            static fn (array $parameter): array => $parameter[0] === $name ? [$name, $value] : $parameter,
            $this->parameters,
        ));
    }

    /**
     * Every parameter named $name removed.
     */
    public function without(string $name): self
    {
        return new self(array_values(array_filter(
            $this->parameters,
            static fn (array $parameter): bool => $parameter[0] !== $name,
        )));
    }

    /**
     * The parameters in the order of $names, each name present once.
     *
     * @param list<string> $names
     */
    public function inOrder(array $names): self
    {
        return new self(array_map(fn (string $name): array => [$name, $this->value($name)], $names));
    }

    /**
     * The query string, without its leading "?".
     */
    public function toString(): string
    {
        return implode('&', array_map(
            static fn (array $parameter): string => $parameter[0] . '=' . $parameter[1],
            $this->parameters,
        ));
    }

    private function has(string $name): bool
    {
        foreach ($this->parameters as [$parameter]) {
            if ($parameter === $name) {
                return true;
            }
        }

        return false;
    }
}
