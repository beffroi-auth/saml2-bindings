<?php

declare(strict_types=1);

/*
 * What capture.php and exchange.php share (README.md of this directory) beyond what every harness of section 9.5 shares
 * (../harness.php: the browser, its reading of a page and of a query string, the captures and the report): the
 * installation's URLs, its test user and its login. Nothing here reads or writes SAML, a query string of a binding or
 * a form of a binding: that is this package's, saml2-bindings, which the two scripts call for every message.
 */

require __DIR__ . '/../harness.php';

const VERSION = '2.5.3.1';
const IDP = 'http://localhost:8091/simplesaml';
const SP = 'http://localhost:8092/simplesaml';
// This package's two roles: nothing listens on port 8093, the exchange is what answers there.
const BINDINGS = 'http://localhost:8093/bindings';
const TEST_USER = 'student';
const TEST_PASSWORD = 'studentpass';

/**
 * The test user's login, from the login page $browser is on to the page that follows it inside the identity provider.
 */
function log_in(Browser $browser): Browser
{
    $login = $browser->form('login form');
    $authState = $login->field('AuthState') ?? throw new RuntimeException(sprintf('no login form at %s', $browser->url));

    return $browser->post($login->action, Beffroi\Saml2\Bindings\Tests\Support\BrowserForm::body([
        ['username', TEST_USER],
        ['password', TEST_PASSWORD],
        ['AuthState', $authState],
    ]))->followWithin(IDP . '/');
}

/**
 * The report of a run of this harness: its captures named with SimpleSAMLphp's version and the date, in received/ or,
 * with --keep, in tests/Fixture/real/.
 *
 * @param list<string> $argv
 */
function simplesamlphp_run(array $argv): Run
{
    return new Run(
        in_array('--keep', $argv, true) ? __DIR__ . '/../../Fixture/real' : __DIR__ . '/received',
        'simplesamlphp-' . VERSION,
    );
}
