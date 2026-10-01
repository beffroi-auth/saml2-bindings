<?php

declare(strict_types=1);

/*
 * The judge of section 9.5 of the specification, SimpleSAMLphp both ways, run by hand and never by the CI (section 12):
 * the installation of tests/Interop/simplesamlphp/, its image built here, the capture between its two parties and the
 * exchange with this package, each script in the phpqa image on the network of the installation, from one task. The
 * README of that directory holds what each step does, its results and its findings. saml2-model's task of the same
 * name, at its commit 9c833c5, under this package's compose project and ports.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\exit_code;
use function Castor\io;
use function Castor\run;

/**
 * The directory of the judge, relative to the root of the repository.
 */
const SIMPLESAMLPHP = 'tests/Interop/simplesamlphp';

#[AsTask(
    description: 'The judge of spec/bindings.md section 9.5, SimpleSAMLphp both ways: without an option, the whole run (install, up, the capture, the exchange, down); each option runs its step alone, in the order listed',
)]
function simplesamlphp(
    #[AsOption(description: 'Start the installation, its image built locally if needed')]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between the installation\'s two parties, every query string and form read by this package (capture.php)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Play the exchange with this package, the installation up: both ways, login and logout, the probes and the measures (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the capture and the exchange: keep what SimpleSAMLphp sent in tests/Fixture/real/, dated, instead of received/',
    )]
    bool $keep = false,
    #[AsOption(description: 'The figure of section 9.6 on the real query strings and forms (timing.php)')]
    bool $timing = false,
    #[AsOption(description: 'Stop the installation')]
    bool $down = false,
): void {
    if (! $up && ! $capture && ! $exchange && ! $timing && ! $down) {
        simplesamlphp_install();
        try {
            simplesamlphp_up();
            simplesamlphp_script('capture.php', $keep);
            simplesamlphp_script('exchange.php', $keep);
        } finally {
            simplesamlphp_down();
        }

        return;
    }
    if ($up) {
        simplesamlphp_install();
        simplesamlphp_up();
    }
    if ($capture) {
        simplesamlphp_script('capture.php', $keep);
    }
    if ($exchange) {
        simplesamlphp_script('exchange.php', $keep);
    }
    if ($timing) {
        simplesamlphp_install();
        phpqa(['php', SIMPLESAMLPHP . '/timing.php']);
    }
    if ($down) {
        simplesamlphp_down();
    }
}

/**
 * What a clean checkout lacks: the package's dependencies, which the scripts load.
 */
function simplesamlphp_install(): void
{
    if (! is_file('vendor/autoload.php')) {
        install();
    }
}

/**
 * The installation up, its image built from installation/Dockerfile; written/, which both parties mount, created here
 * so that Docker does not create it as root.
 */
function simplesamlphp_up(): void
{
    if (! is_dir(SIMPLESAMLPHP . '/written')) {
        mkdir(SIMPLESAMLPHP . '/written');
    }
    run([
        'docker',
        'compose',
        '-f',
        SIMPLESAMLPHP . '/installation/compose.yaml',
        'up',
        '-d',
        '--build',
        '--force-recreate',
    ]);
    for ($attempt = 0; $attempt < 60; ++$attempt) {
        $idp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8091/simplesaml/module.php/saml/idp/metadata',
        ], context: context()->withQuiet());
        $sp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8092/simplesaml/module.php/saml/sp/metadata/for-bindings',
        ], context: context()->withQuiet());
        if ($idp === 0 && $sp === 0) {
            return;
        }
        sleep(1);
    }
    io()->error('SimpleSAMLphp did not come up.');
    exit(1);
}

/**
 * A script of the judge in the phpqa image, on the network of the installation, localhost:8091 and localhost:8092
 * pinned to its two containers so that every URL stays the one the installation knows.
 */
function simplesamlphp_script(string $script, bool $keep): void
{
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'saml2-bindings-simplesamlphp_default',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'EXCHANGE_CONNECT_TO=localhost:8091:idp:80,localhost:8092:sp:80',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', php_version()),
        'php',
        SIMPLESAMLPHP . '/' . $script,
        ...($keep ? ['--keep'] : []),
    ]);
}

function simplesamlphp_down(): void
{
    run(['docker', 'compose', '-f', SIMPLESAMLPHP . '/installation/compose.yaml', 'down']);
}
