<?php

declare(strict_types=1);

/*
 * What capture.php and exchange.php share (README.md of this directory): the browser they play, its reading of a page,
 * the captures they keep and the steps they report. Nothing here reads or writes SAML, a query string of a binding or
 * a form of a binding: that is this package's, saml2-bindings, which the two scripts call for every message.
 */

use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Psr\Clock\ClockInterface;

require __DIR__ . '/../../../vendor/autoload.php';

const VERSION = '2.5.3.1';
const IDP = 'http://localhost:8091/simplesaml';
const SP = 'http://localhost:8092/simplesaml';
// This package's two roles: nothing listens on port 8093, the exchange is what answers there.
const BINDINGS = 'http://localhost:8093/bindings';
const TEST_USER = 'student';
const TEST_PASSWORD = 'studentpass';

/**
 * The live clock, the one the model's validators read in a run: the suite replays a capture with a frozen one.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('now', new DateTimeZone('UTC'));
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

        return new self($action === null || $action === '' ? $url : self::resolve($action, $url), $fields);
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
     * An absolute action as it is; a path on the page's origin.
     */
    private static function resolve(string $action, string $url): string
    {
        if (preg_match('~^https?://~', $action) === 1) {
            return $action;
        }
        $origin = (string) preg_replace('~^(https?://[^/]+).*$~', '$1', $url);

        return str_starts_with($action, '/') ? $origin . $action : $origin . '/' . $action;
    }
}

/**
 * A browser with one cookie jar: one hop per call, never following a redirect by itself. EXCHANGE_CONNECT_TO pins
 * localhost:8091 and localhost:8092 to the containers, so that the Host header, every entity ID and every Destination
 * stay those the installation knows.
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
        while (in_array($this->status, [302, 303], true) && str_starts_with((string) $this->location, $prefix)) {
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
     * The test user's login, from the login page the browser is on to the page that follows it inside the identity
     * provider.
     */
    public function logIn(): self
    {
        $login = $this->form('login form');
        $authState = $login->field('AuthState') ?? throw new RuntimeException(sprintf('no login form at %s', $this->url));

        return $this->post($login->action, BrowserForm::body([
            ['username', TEST_USER],
            ['password', TEST_PASSWORD],
            ['AuthState', $authState],
        ]))->followWithin(IDP . '/');
    }

    /**
     * What SimpleSAMLphp's error page says, when the answer is one: the exception it names ("Caused by:", shown since
     * showerrors is true by default), or else its title, the name of its error code ("Invalid certificate signature"
     * for NOTVALIDCERTSIGNATURE, which Message::checkSign() raises whatever made the verification fail).
     */
    public function error(): string
    {
        if ($this->status < 400) {
            return '';
        }
        if (preg_match('/Caused by: ([^\n<]+)/', $this->body, $match) === 1) {
            return ': ' . trim(html_entity_decode($match[1], ENT_QUOTES | ENT_HTML5));
        }
        $title = trim(Dom\HTMLDocument::createFromString($this->body, LIBXML_NOERROR)->title);

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

        return $this;
    }
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
 * The run's report: one line per step and measure, the failures counted, and the captures kept, bytes as received,
 * named with SimpleSAMLphp's version and the date, in received/ or, with --keep, in tests/Fixture/real/.
 */
final class Run
{
    /**
     * @var list<string>
     */
    public array $failures = [];

    private readonly string $today;

    public function __construct(private readonly string $directory)
    {
        if (! is_dir($directory)) {
            mkdir($directory);
        }
        $this->today = new SystemClock()->now()->format('Y-m-d');
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
     * What SimpleSAMLphp sent, bytes as received, no line feed added.
     */
    public function keep(string $what, string $bytes, string $extension = 'txt'): void
    {
        $file = sprintf('%s/simplesamlphp-%s-%s-%s.%s', $this->directory, VERSION, $what, $this->today, $extension);
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
