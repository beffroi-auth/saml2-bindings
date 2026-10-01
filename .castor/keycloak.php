<?php

declare(strict_types=1);

/*
 * The second target of the judge of section 9.5 of the specification, Keycloak both ways, reinforcing the judge without
 * being a condition of it, run by hand and never by the CI (section 12): the installation of tests/Interop/keycloak/,
 * the capture between its two realms and the exchange with this package, each script in the phpqa image inside the
 * network namespace of the Keycloak container, from one task. The README of that directory holds what each step does,
 * its results and its findings. saml2-model's task of the same name, at its commit 9c833c5, under this package's compose
 * project and port.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * The directory of the harness, relative to the root of the repository.
 */
const KEYCLOAK_HARNESS = 'tests/Interop/keycloak';

#[AsTask(
    description: 'Keycloak against this package, both ways (spec/bindings.md section 9.5): without an option, the whole run (install, up, the capture, the exchange, down); each option runs its step alone, in the order listed',
)]
function keycloak(
    #[AsOption(description: 'Start Keycloak, the realms of tests/Interop/keycloak/realms/ imported with new keys')]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between realm sp\'s broker and realm idp, every query string and form read by this package (capture.php)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Configure Keycloak from this package\'s metadata and play the exchange, Keycloak up: both ways, login and logout, the probes and the measures (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the capture and the exchange: keep what Keycloak sent in tests/Fixture/real/, dated, instead of received/; the realm keys being new at every up, run both in one up',
    )]
    bool $keep = false,
    #[AsOption(description: 'Stop Keycloak and remove its container, its realms and keys with it')]
    bool $down = false,
): void {
    if (! $up && ! $capture && ! $exchange && ! $down) {
        keycloak_install();
        try {
            keycloak_up();
            keycloak_script('capture.php', $keep);
            keycloak_script('exchange.php', $keep);
        } finally {
            keycloak_down();
        }

        return;
    }
    if ($up) {
        keycloak_install();
        keycloak_up();
    }
    if ($capture) {
        keycloak_script('capture.php', $keep);
    }
    if ($exchange) {
        keycloak_script('exchange.php', $keep);
    }
    if ($down) {
        keycloak_down();
    }
}

/**
 * What a clean checkout lacks: the package's dependencies, which the scripts load.
 */
function keycloak_install(): void
{
    if (! is_file('vendor/autoload.php')) {
        install();
    }
}

/**
 * Keycloak up, the realms imported at its first start with new keys; the scripts wait for it to answer.
 */
function keycloak_up(): void
{
    run(['docker', 'compose', '-f', KEYCLOAK_HARNESS . '/compose.yaml', 'up', '-d']);
}

/**
 * A script of the harness in the phpqa image, inside the network namespace of the Keycloak container: localhost:8190 is
 * Keycloak there, the host and the port of every URL it builds and checks.
 */
function keycloak_script(string $script, bool $keep): void
{
    $container = trim(capture(
        ['docker', 'compose', '-f', KEYCLOAK_HARNESS . '/compose.yaml', 'ps', '-q', 'keycloak'],
        context()->withQuiet()->withAllowFailure(),
        onFailure: '',
    ));
    if ($container === '') {
        io()->error('Keycloak is not running: castor keycloak --up.');
        exit(1);
    }
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'container:' . $container,
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'XDEBUG_MODE=off',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', php_version()),
        'php',
        KEYCLOAK_HARNESS . '/' . $script,
        ...($keep ? ['--keep'] : []),
    ]);
}

function keycloak_down(): void
{
    run(['docker', 'compose', '-f', KEYCLOAK_HARNESS . '/compose.yaml', 'down']);
}
