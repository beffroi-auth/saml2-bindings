<?php

declare(strict_types=1);

/*
 * Prints, as Markdown tables, the measures of the query strings and forms of a directory that match a glob, for the
 * tables of the READMEs of the harnesses of section 9.5 (simplesamlphp/, keycloak/) and the bounds of section 7 of
 * spec/bindings.md: their length, their parameters or fields in order, the SigAlg and the escaping as sent, the length
 * of the RelayState and of the Signature once decoded, and the length of the message: for a query string, the smallest
 * maxInflatedBytes under which RedirectReceiver reads it, found by bisection, the package being the one inflater here;
 * for a form, the characters of its base64 text, the bound maxFormValueBytes reads, and whether a line break wraps it.
 * saml2-model's measure.php, at its commit 9c833c5, measured the XML; the package measures what carried it.
 *
 * From the root of the repository:
 *   docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 \
 *       php tests/Interop/measure.php tests/Fixture/real 'simplesamlphp-*.txt'
 * and 'keycloak-*.txt' for Keycloak's.
 */

use Beffroi\Saml2\Bindings\BindingLimits;
use Beffroi\Saml2\Bindings\Exception\LimitExceeded;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Model\SamlLoader;

require __DIR__ . '/../../vendor/autoload.php';

$files = glob(rtrim($argv[1] ?? '.', '/') . '/' . ($argv[2] ?? '*.txt')) ?: [];
sort($files);

$queries = [];
$forms = [];
foreach ($files as $file) {
    $bytes = (string) file_get_contents($file);
    $name = '`' . basename($file) . '`';
    if (str_contains($file, '-form-')) {
        $forms[] = form($name, $bytes);
    } else {
        $queries[] = query($name, $bytes, str_contains($file, 'authnrequest'));
    }
}

table(['Query string', 'Bytes', 'Parameters', 'SigAlg', 'Escapes', 'RelayState, bytes', 'Signature, bytes', 'Inflated, bytes'], $queries);
table(['Form, the body a browser posts', 'Bytes', 'Fields', 'Message, base64 characters', 'Line breaks', 'RelayState, bytes'], $forms);

/**
 * @return list<string>
 */
function query(string $name, string $query, bool $authnRequest): array
{
    $raw = [];
    foreach (explode('&', $query) as $parameter) {
        [$key, $value] = explode('=', $parameter, 2) + [1 => ''];
        $raw[$key] = $value;
    }
    $signature = isset($raw['Signature']) ? rawurldecode($raw['Signature']) : null;
    $lower = preg_match_all('/%(?:[0-9a-f][a-f]|[a-f][0-9a-f])/', $query);

    return [
        $name,
        number_format(strlen($query), 0, '.', ' '),
        implode(', ', array_keys($raw)),
        isset($raw['SigAlg']) ? (string) preg_replace('/^.*%23/', '', $raw['SigAlg']) : 'none',
        sprintf(
            '%d, %s; %d `+`, %d `%%7E`',
            preg_match_all('/%[0-9A-Fa-f]{2}/', $query),
            $lower === 0 ? 'uppercase' : $lower . ' lowercase',
            substr_count($query, '+'),
            substr_count($query, '%7E'),
        ),
        isset($raw['RelayState']) ? (string) strlen(urldecode($raw['RelayState'])) : 'absent',
        $signature === null ? 'none' : (string) (intdiv(strlen($signature), 4) * 3 - substr_count($signature, '=')),
        inflated($query, $authnRequest),
    ];
}

/**
 * The smallest maxInflatedBytes under which RedirectReceiver reads $query, or why it cannot be measured.
 */
function inflated(string $query, bool $authnRequest): string
{
    $reads = static function (int $bound) use ($query, $authnRequest): bool {
        $receiver = new RedirectReceiver(SamlLoader::create(), new BindingLimits(maxInflatedBytes: $bound));
        try {
            $authnRequest ? $receiver->authnRequest($query) : $receiver->logoutMessage($query);
        } catch (LimitExceeded) {
            return false;
        }

        return true;
    };
    try {
        if (! $reads(65_536)) {
            return 'over 65 536';
        }
    } catch (Throwable $refused) {
        return sprintf('not read: %s', $refused->getMessage());
    }
    [$low, $high] = [1, 65_536];
    while ($low < $high) {
        $middle = intdiv($low + $high, 2);
        if ($reads($middle)) {
            $high = $middle;
        } else {
            $low = $middle + 1;
        }
    }

    return number_format($low, 0, '.', ' ');
}

/**
 * @return list<string>
 */
function form(string $name, string $body): array
{
    $fields = BrowserForm::parsed($body);
    $message = $fields['SAMLResponse'] ?? $fields['SAMLRequest'] ?? '';
    $message = is_string($message) ? $message : '';
    $relayState = $fields['RelayState'] ?? null;

    return [
        $name,
        number_format(strlen($body), 0, '.', ' '),
        implode(', ', array_map(strval(...), array_keys($fields))),
        number_format(strlen($message), 0, '.', ' '),
        preg_match('/[\r\n]/', $message) === 1 ? 'yes' : 'none',
        is_string($relayState) ? (string) strlen($relayState) : 'absent',
    ];
}

/**
 * @param list<string>       $header
 * @param list<list<string>> $rows
 */
function table(array $header, array $rows): void
{
    if ($rows === []) {
        return;
    }
    printf("| %s |\n|%s\n", implode(' | ', $header), str_repeat('---|', count($header)));
    foreach ($rows as $row) {
        printf("| %s |\n", implode(' | ', $row));
    }
    echo "\n";
}
