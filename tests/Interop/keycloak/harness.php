<?php

declare(strict_types=1);

/*
 * What capture.php and exchange.php share (README.md of this directory) beyond what every harness of section 9.5 shares
 * (../harness.php: the browser, its reading of a page and of a query string, the captures and the report): Keycloak's
 * URLs, its test user, its login, the OpenID Connect client that starts a login at realm sp, its admin REST API and its
 * error page. Nothing here reads or writes SAML, a query string of a binding or a form of a binding: that is this
 * package's, saml2-bindings, which the two scripts call for every message. The scripts run in the network namespace of
 * the Keycloak container (castor keycloak), where localhost:8190 is Keycloak, as in every URL it builds and checks.
 */

use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;

require __DIR__ . '/../harness.php';

const VERSION = '26.7.4';
const KEYCLOAK = 'http://localhost:8190';
// The redirect URI of the client capture of realms/sp.json: nothing answers there, the scripts read the redirect.
const CLIENT_REDIRECT = KEYCLOAK . '/capture';
// The disposable test user of realms/idp.json.
const TEST_USER = 'alice';
const TEST_PASSWORD = 'alice';

/**
 * The report of a run of this harness: its captures named with Keycloak's version and the date, in received/ or, with
 * --keep, in tests/Fixture/real/.
 *
 * @param list<string> $argv
 */
function keycloak_run(array $argv): Run
{
    return new Run(
        in_array('--keep', $argv, true) ? __DIR__ . '/../../Fixture/real' : __DIR__ . '/received',
        'keycloak-' . VERSION,
    );
}

/**
 * Keycloak answering, the realms imported: 180 s at most.
 */
function wait_for_keycloak(): void
{
    for ($attempt = 0; $attempt < 90; ++$attempt) {
        try {
            if (new Browser()->get(KEYCLOAK . '/realms/sp/broker/idp/endpoint/descriptor')->status === 200) {
                return;
            }
        } catch (RuntimeException) {
            // not listening yet
        }
        sleep(2);
    }

    throw new RuntimeException('Keycloak did not answer on port 8190 within 180 s');
}

/**
 * The start of a login at the OpenID Connect client $client of realm sp, sent to its SAML identity provider $alias.
 */
function client_login(string $alias, string $client = 'capture'): string
{
    return KEYCLOAK . '/realms/sp/protocol/openid-connect/auth?' . BrowserForm::body([
        ['client_id', $client],
        ['response_type', 'code'],
        ['scope', 'openid'],
        ['redirect_uri', CLIENT_REDIRECT],
        ['kc_idp_hint', $alias],
    ]);
}

/**
 * The end of the session of the client capture of realm sp, its ID token as the hint.
 */
function client_logout(string $idToken): string
{
    return KEYCLOAK . '/realms/sp/protocol/openid-connect/logout?' . BrowserForm::body([
        ['id_token_hint', $idToken],
        ['post_logout_redirect_uri', CLIENT_REDIRECT],
    ]);
}

/**
 * The tokens of the client capture for the code its redirect URI carries: the login of realm sp completed.
 *
 * @return array<string, mixed>
 */
function client_tokens(Browser $browser, string $redirect): array
{
    $code = query_value(split_url($redirect)[1], 'code') ?? throw new RuntimeException('no code at the redirect URI of the client');
    $tokens = json_decode($browser->post(KEYCLOAK . '/realms/sp/protocol/openid-connect/token', BrowserForm::body([
        ['grant_type', 'authorization_code'],
        ['code', urldecode($code)],
        ['redirect_uri', CLIENT_REDIRECT],
        ['client_id', 'capture'],
    ]))->body, true);
    if (! is_array($tokens) || ! is_string($tokens['id_token'] ?? null) || ! is_string($tokens['access_token'] ?? null)) {
        throw new RuntimeException(sprintf('no tokens for the code, HTTP %d', $browser->status));
    }

    return $tokens;
}

/**
 * What realm sp's userinfo endpoint says of the session of $accessToken: its claims, or null once the session is gone.
 *
 * @return array<string, mixed>|null
 */
function client_userinfo(string $accessToken): ?array
{
    $curl = curl_init(KEYCLOAK . '/realms/sp/protocol/openid-connect/userinfo');
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $accessToken]]);
    $body = (string) curl_exec($curl);
    if (curl_getinfo($curl, CURLINFO_RESPONSE_CODE) !== 200) {
        return null;
    }
    $claims = json_decode($body, true);

    return is_array($claims) ? $claims : null;
}

/**
 * The test user's login at realm idp, from its login page, where the browser is, to the page that follows it inside
 * realm idp.
 */
function log_in(Browser $browser): Browser
{
    $login = $browser->form('login form of realm idp');

    return $browser->post($login->action, BrowserForm::body([
        ['username', TEST_USER],
        ['password', TEST_PASSWORD],
        ['credentialId', ''],
    ]))->followWithin(KEYCLOAK . '/realms/idp/');
}

/**
 * Whether the page is realm idp's login page: an AuthnRequest it accepted, the user not logged in yet.
 */
function login_page(Browser $browser): bool
{
    return $browser->status === 200 && str_contains($browser->body, 'id="kc-form-login"');
}

/**
 * Whether the page is the auto-submitted form of Keycloak's HTTP-POST binding.
 */
function post_binding_page(Browser $browser): bool
{
    return $browser->status === 200 && str_contains($browser->body, 'name="saml-post-binding"');
}

/**
 * A refusal by Keycloak: its error page, neither a redirect nor a form going on.
 */
function keycloak_refused(Browser $browser): bool
{
    return $browser->status >= 400 && $browser->location === null && ! post_binding_page($browser);
}

/**
 * Keycloak's admin REST API, with the disposable administrator of compose.yaml.
 */
final class Admin
{
    private readonly string $token;

    public function __construct()
    {
        $answer = json_decode(new Browser()->post(KEYCLOAK . '/realms/master/protocol/openid-connect/token', BrowserForm::body([
            ['grant_type', 'password'],
            ['client_id', 'admin-cli'],
            ['username', 'admin'],
            ['password', 'admin'],
        ]))->body, true);
        $this->token = is_array($answer) && is_string($answer['access_token'] ?? null)
            ? $answer['access_token']
            : throw new RuntimeException('no token for the administrator');
    }

    /**
     * A JSON answer, decoded.
     *
     * @param array<mixed>|null $json
     * @param list<int>         $expect
     *
     * @return array<mixed>
     */
    public function json(string $method, string $path, ?array $json = null, array $expect = [200]): array
    {
        $body = $this->request($method, $path, $json === null ? null : (string) json_encode($json, JSON_UNESCAPED_SLASHES), 'application/json', $expect);
        $value = json_decode($body, true);

        return is_array($value) ? $value : [];
    }

    /**
     * The status of a call whose answer has no body worth reading.
     *
     * @param array<mixed>|null $json
     * @param list<int>         $expect
     */
    public function call(string $method, string $path, ?array $json = null, array $expect = [204]): void
    {
        $this->request($method, $path, $json === null ? null : (string) json_encode($json, JSON_UNESCAPED_SLASHES), 'application/json', $expect);
    }

    /**
     * A document posted as it is, $type its content type, or as the file of a multipart form when $field names it.
     *
     * @return array<mixed>
     */
    public function upload(string $path, string $document, string $type, ?string $field = null, array $fields = []): array
    {
        $body = $field === null
            ? $this->request('POST', $path, $document, $type, [200])
            : $this->request('POST', $path, [...$fields, $field => new CURLStringFile($document, 'metadata.xml', $type)], null, [200]);
        $value = json_decode($body, true);

        return is_array($value) ? $value : [];
    }

    /**
     * @param string|array<string, mixed>|null $body
     * @param list<int>                         $expect
     */
    private function request(string $method, string $path, string|array|null $body, ?string $type, array $expect): string
    {
        $curl = curl_init(KEYCLOAK . $path);
        $headers = ['Authorization: Bearer ' . $this->token];
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CUSTOMREQUEST => $method]);
        if ($body !== null) {
            if ($type !== null) {
                $headers[] = 'Content-Type: ' . $type;
            }
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        $answer = (string) curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if (! in_array($status, $expect, true)) {
            throw new RuntimeException(sprintf('%s %s: HTTP %d %s', $method, $path, $status, substr($answer, 0, 300)));
        }

        return $answer;
    }
}

/**
 * Settings as one line, a long value by its length.
 *
 * @param array<mixed> $settings
 */
function settings(array $settings): string
{
    ksort($settings);
    $shown = [];
    foreach ($settings as $name => $value) {
        $value = is_scalar($value) ? (string) $value : (string) json_encode($value);
        $shown[] = $name . '=' . (strlen($value) > 64 ? '<' . strlen($value) . ' characters>' : $value);
    }

    return implode(', ', $shown);
}
