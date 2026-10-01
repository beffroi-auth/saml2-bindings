<?php

declare(strict_types=1);

/*
 * What the harnesses of section 9.5 share, SimpleSAMLphp's (simplesamlphp/) and Keycloak's (keycloak/): the browser they
 * play, its reading of a page, the reading of a query string as it arrived, the captures they keep and the steps they
 * report. Nothing here reads or writes SAML, a query string of a binding or a form of a binding: that is this package's,
 * saml2-bindings, which every script calls for every message. The one exception is signed_by_hand(), named so, which
 * builds and signs the octets of a query string for the measures of section 9.5 point 4 only, where they need what the
 * package refuses to write.
 */

use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../vendor/autoload.php';

// The SigAlg of RSA with SHA-512 as a query string carries it, for the probe that changes the SigAlg after signing.
const RSA_SHA512_ENCODED = 'http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512';

/**
 * The live clock, the one the model's validators read in a run: the suite replays a capture with a frozen one.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }

    /**
     * Now, to the second: the writers write times to the second, and the documents say what the objects hold.
     */
    public function second(): DateTimeImmutable
    {
        $now = $this->now();

        return $now->setTime((int) $now->format('H'), (int) $now->format('i'), (int) $now->format('s'));
    }
}

/**
 * A form of a page, as a browser reads it: its action resolved against the page's URL, and its successful controls,
 * the named inputs that are neither disabled nor a button, in the order of the document (HTML, "constructing the entry
 * list"). The page is parsed by PHP's HTML5 parser, Dom\HTMLDocument, which decodes the character references of the
 * attributes as a browser does.
 */
final readonly class Form
{
    /**
     * @param list<array{string, string}> $fields
     */
    public function __construct(
        public string $action,
        public array $fields,
    ) {
    }

    /**
     * The first form of $html, or null when the page holds none.
     */
    public static function of(string $html, string $url): ?self
    {
        $document = Dom\HTMLDocument::createFromString($html, LIBXML_NOERROR);
        $form = $document->querySelector('form');
        if ($form === null) {
            return null;
        }
        $fields = [];
        foreach ($form->querySelectorAll('input[name]') as $input) {
            $type = strtolower($input->getAttribute('type') ?? 'text');
            if ($input->hasAttribute('disabled') || in_array($type, ['submit', 'button', 'image', 'reset', 'file'], true)) {
                continue;
            }
            $fields[] = [(string) $input->getAttribute('name'), (string) $input->getAttribute('value')];
        }
        $action = $form->getAttribute('action');

        return new self($action === null || $action === '' ? $url : resolve_url($action, $url), $fields);
    }

    /**
     * The value of the field $name, or null.
     */
    public function field(string $name): ?string
    {
        foreach ($this->fields as [$field, $value]) {
            if ($field === $name) {
                return $value;
            }
        }

        return null;
    }

    /**
     * The names of the fields, in their order.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_map(static fn (array $field): string => $field[0], $this->fields);
    }

    /**
     * The body a browser posts for this form, application/x-www-form-urlencoded (tests/Support/BrowserForm.php).
     */
    public function body(): string
    {
        return BrowserForm::body($this->fields);
    }

    /**
     * Whether the base64 of the field $name is wrapped, a line break in it.
     */
    public function wrapped(string $name): bool
    {
        return preg_match('/[\r\n]/', (string) $this->field($name)) === 1;
    }
}

/**
 * A browser with one cookie jar: one hop per call, never following a redirect by itself, a relative Location resolved
 * against the URL it answers. EXCHANGE_CONNECT_TO, when set, pins host:port pairs to containers, so that the Host header,
 * every entity ID and every Destination stay those the installation knows.
 */
final class Browser
{
    public int $status = 0;

    public ?string $location = null;

    public string $body = '';

    public string $url = '';

    private CurlHandle $curl;

    public function __construct()
    {
        $this->curl = curl_init();
        curl_setopt_array($this->curl, [
            CURLOPT_COOKIEFILE => '',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HEADERFUNCTION => function (CurlHandle $curl, string $header): int {
                if (preg_match('/^Location:\s*(\S+)\s*$/i', $header, $match) === 1) {
                    $this->location = $match[1];
                }

                return strlen($header);
            },
        ]);
        $connectTo = getenv('EXCHANGE_CONNECT_TO');
        if (is_string($connectTo) && $connectTo !== '') {
            curl_setopt($this->curl, CURLOPT_CONNECT_TO, explode(',', $connectTo));
        }
    }

    public function get(string $url): self
    {
        curl_setopt($this->curl, CURLOPT_HTTPGET, true);

        return $this->send($url);
    }

    /**
     * A post of an application/x-www-form-urlencoded body, as a browser submits a form.
     */
    public function post(string $url, string $body): self
    {
        curl_setopt_array($this->curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        return $this->send($url);
    }

    /**
     * Submits a form of a page, its fields encoded as a browser encodes them.
     */
    public function submit(Form $form): self
    {
        return $this->post($form->action, $form->body());
    }

    /**
     * The target of the redirect this answer is, or a failure naming what was expected.
     */
    public function redirect(string $expected): string
    {
        if (! in_array($this->status, [302, 303], true) || $this->location === null) {
            throw new RuntimeException(sprintf('expected %s, got HTTP %d at %s%s', $expected, $this->status, $this->url, $this->error()));
        }

        return $this->location;
    }

    /**
     * Follows the redirects, one hop at a time, while they stay under $prefix, as a browser would inside one party.
     */
    public function followWithin(string $prefix): self
    {
        for ($hops = 0; in_array($this->status, [302, 303], true) && str_starts_with((string) $this->location, $prefix); ++$hops) {
            if ($hops === 20) {
                throw new RuntimeException(sprintf('more than 20 redirects under %s', $prefix));
            }
            $this->get((string) $this->location);
        }

        return $this;
    }

    /**
     * The first form of the page, or a failure.
     */
    public function form(string $what): Form
    {
        return Form::of($this->body, $this->url)
            ?? throw new RuntimeException(sprintf('no %s at %s (HTTP %d)%s', $what, $this->url, $this->status, $this->error()));
    }

    /**
     * What the error page of a peer says, when the answer is one: the exception SimpleSAMLphp names ("Caused by:",
     * shown since showerrors is true by default), the message of Keycloak's error page (its kc-error-message), or else
     * the title of the page ("Invalid certificate signature", the name of SimpleSAMLphp's error code
     * NOTVALIDCERTSIGNATURE, which Message::checkSign() raises whatever made the verification fail).
     */
    public function error(): string
    {
        if ($this->status < 400) {
            return '';
        }
        if (preg_match('/Caused by: ([^\n<]+)/', $this->body, $match) === 1) {
            return ': ' . trim(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5));
        }
        $document = Dom\HTMLDocument::createFromString($this->body, LIBXML_NOERROR);
        $message = $document->querySelector('#kc-error-message');
        if ($message !== null) {
            return sprintf(': "%s"', trim((string) preg_replace('/\s+/', ' ', $message->textContent)));
        }
        $title = trim($document->title);

        return $title === '' ? '' : sprintf(': "%s"', $title);
    }

    private function send(string $url): self
    {
        $this->location = null;
        curl_setopt($this->curl, CURLOPT_URL, $url);
        $body = curl_exec($this->curl);
        if (! is_string($body)) {
            throw new RuntimeException(sprintf('%s: %s', $url, curl_error($this->curl)));
        }
        $this->url = $url;
        $this->body = $body;
        $this->status = (int) curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE);
        if ($this->location !== null) {
            $this->location = resolve_url($this->location, $url);
        }

        return $this;
    }
}

/**
 * An absolute URL as it is; a path on the origin of $base.
 */
function resolve_url(string $url, string $base): string
{
    if (preg_match('~^https?://~', $url) === 1) {
        return $url;
    }
    $origin = (string) preg_replace('~^(https?://[^/]+).*$~', '$1', $base);

    return str_starts_with($url, '/') ? $origin . $url : $origin . '/' . $url;
}

/**
 * A URL split at its first "?": the endpoint and the raw query string, as the consumer reads it from QUERY_STRING
 * (section 6.8 of spec/bindings.md), never decoded.
 *
 * @return array{string, string}
 */
function split_url(string $url): array
{
    $parts = explode('?', $url, 2);

    return [$parts[0], $parts[1] ?? ''];
}

/**
 * The raw value of $name in $query, still percent-encoded, or null.
 */
function query_value(string $query, string $name): ?string
{
    foreach (explode('&', $query) as $parameter) {
        if (str_starts_with($parameter, $name . '=')) {
            return substr($parameter, strlen($name) + 1);
        }
    }

    return null;
}

/**
 * $query with the raw value of $name replaced, or the parameter removed when $value is null.
 */
function query_replaced(string $query, string $name, ?string $value): string
{
    $parameters = [];
    foreach (explode('&', $query) as $parameter) {
        if (! str_starts_with($parameter, $name . '=')) {
            $parameters[] = $parameter;
        } elseif ($value !== null) {
            $parameters[] = $name . '=' . $value;
        }
    }

    return implode('&', $parameters);
}

/**
 * The names of the parameters of $query, in their order.
 *
 * @return list<string>
 */
function query_names(string $query): array
{
    return array_map(static fn (string $parameter): string => explode('=', $parameter, 2)[0], explode('&', $query));
}

/**
 * What a query string a peer sent is made of: its length, its parameters in order, its SigAlg as sent, its escaping,
 * the case of its hexadecimal digits and its "+", "%20" and "%7E".
 */
function query_described(string $query): string
{
    $lower = preg_match_all('/%(?:[0-9a-f][a-f]|[a-f][0-9a-f])/', $query);
    $upper = preg_match_all('/%[0-9A-F]{2}/', $query);

    return sprintf(
        '%d bytes: parameters %s; SigAlg %s; %d escapes, %s, %d "+", %d "%%20", %d "%%7E"',
        strlen($query),
        implode(', ', query_names($query)),
        query_value($query, 'SigAlg') ?? 'absent',
        $upper + $lower,
        $lower === 0 ? 'uppercase hexadecimal only' : $lower . ' in lowercase',
        substr_count($query, '+'),
        substr_count($query, '%20'),
        substr_count($query, '%7E'),
    );
}

/**
 * The four changes of a query string this package signed, by name, each a URL a peer must refuse: its RelayState, its
 * SigAlg, its message, taken from $other, another URL this package wrote, so that no octet is built by hand, and its
 * signature removed.
 *
 * @return array<string, string>
 */
function query_tampered(string $genuine, string $other, string $parameter): array
{
    [$endpoint, $query] = split_url($genuine);
    $message = query_value(split_url($other)[1], $parameter) ?? throw new LogicException('the other URL carries its message');

    return [
        'whose RelayState was changed after signing' => $endpoint . '?' . query_replaced($query, 'RelayState', 'bindings-proof'),
        'whose SigAlg was changed after signing, RSA-SHA256 to RSA-SHA512' => $endpoint . '?' . query_replaced($query, 'SigAlg', RSA_SHA512_ENCODED),
        'whose message was changed after signing, another of this package' => $endpoint . '?' . query_replaced($query, $parameter, $message),
        'whose Signature and SigAlg were removed' => $endpoint . '?' . query_replaced(query_replaced($query, 'Signature', null), 'SigAlg', null),
    ];
}

/**
 * For the measures of section 9.5 point 4 only: the unsigned URL RedirectSender wrote, then "&SigAlg=" and $uri, signed
 * by hand with $privateKeyPem and $digest, then "&Signature=": what the package refuses to write (an RSA-SHA1
 * signature, a SigAlg off its list, a "+" in a signed RelayState).
 */
function signed_by_hand(string $unsigned, string $uri, int $digest, string $privateKeyPem): string
{
    [$endpoint, $query] = split_url($unsigned);
    $octets = $query . '&SigAlg=' . rawurlencode($uri);
    if (! openssl_sign($octets, $signature, $privateKeyPem, $digest)) {
        throw new RuntimeException('OpenSSL did not sign');
    }

    return $endpoint . '?' . $octets . '&Signature=' . rawurlencode(base64_encode($signature));
}

/**
 * The RelayState a field or a parameter holds, against the one this package sent.
 */
function relay_state_of(?string $received, ?string $sent): string
{
    if ($received === null) {
        return $sent === null ? 'absent, none sent' : 'ABSENT, one sent';
    }

    return sprintf('%s, %d bytes%s', var_export($received, true), strlen($received), $received === $sent ? ', as sent' : ', NOT as sent');
}

/**
 * The run's report: one line per step and measure, the failures counted, and the captures kept, bytes as received,
 * named with the peer, its version and the date ($prefix, "simplesamlphp-2.5.3.1" for instance), in $directory.
 */
final class Run
{
    /**
     * @var list<string>
     */
    public array $failures = [];

    private readonly string $today;

    public function __construct(
        private readonly string $directory,
        private readonly string $prefix,
    ) {
        if (! is_dir($directory)) {
            mkdir($directory);
        }
        $now = new SystemClock()->now();
        $this->today = $now->format('Y-m-d');
        $this->say(sprintf('PHP %s, curl %s, %s', PHP_VERSION, curl_version()['version'] ?? '?', $now->format('Y-m-d\TH:i:s\Z')));
    }

    public function say(string $line): void
    {
        fwrite(STDOUT, $line . "\n");
    }

    /**
     * A step: its name, then its lines, or FAIL and why; a failure is counted and the run goes on.
     */
    public function step(string $name, Closure $run): mixed
    {
        $this->say('== ' . $name);
        try {
            return $run();
        } catch (Throwable $failure) {
            $this->failures[] = $name;
            $this->say(sprintf('FAIL %s: %s: %s', $name, $failure::class, $failure->getMessage()));

            return null;
        }
    }

    /**
     * What the peer sent, bytes as received, no line feed added.
     */
    public function keep(string $what, string $bytes, string $extension = 'txt'): void
    {
        $file = sprintf('%s/%s-%s-%s.%s', $this->directory, $this->prefix, $what, $this->today, $extension);
        file_put_contents($file, $bytes);
        $this->say(sprintf('kept %s (%d bytes)', basename($file), strlen($bytes)));
    }

    public function exit(): never
    {
        $this->say($this->failures === []
            ? 'every step green'
            : sprintf('%d step(s) failed: %s', count($this->failures), implode('; ', $this->failures)));
        exit($this->failures === [] ? 0 : 1);
    }
}
