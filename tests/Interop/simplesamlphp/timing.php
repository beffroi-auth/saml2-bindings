<?php

declare(strict_types=1);

/*
 * The figure of section 9.6 of spec/bindings.md, measured on SimpleSAMLphp's real query strings and forms: how long
 * this package and the model take from the raw query string of a signed AuthnRequest to AcceptedAuthnRequest, its
 * parameters read, its signature verified, its message decoded, inflated, loaded and validated; and, beside it, from
 * the fields of a response's form to AcceptedAssertion. The metadata are read once, as a consumer keeps them; the
 * Loader, the receiver and the validator are made at each run, with a new replay store, the clock frozen at the
 * capture. Each case runs 20 times to warm up, then 500 times; the median and the 95th percentile are printed in
 * milliseconds. Outside the suite, which reads no clock (section 9.6). saml2-model's timing.php, at its commit
 * 9c833c5, on the inputs of this package.
 *
 * From the root of the repository, on each PHP of the CI (castor simplesamlphp --timing runs it):
 *   docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/timing.php
 */

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\FrozenClock;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Bindings\Tests\Support\TestKeys;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;

require __DIR__ . '/../../../vendor/autoload.php';

$real = __DIR__ . '/../../Fixture/real/';

$metadata = static function (string $file, FrozenClock $clock) use ($real): EntityDescriptor {
    return new MetadataReader(SamlLoader::create(), $clock)
        ->readTrusted(SamlLoader::create()->load((string) file_get_contents($real . $file)));
};

$bindingsIdp = new IdentityProvider(
    'http://localhost:8093/bindings/idp',
    [TestKeys::certificate('idp')],
    [],
    [new Endpoint(Binding::HttpRedirect, 'http://localhost:8093/bindings/idp/sso')],
    [new Endpoint(Binding::HttpRedirect, 'http://localhost:8093/bindings/idp/slo')],
    [NameIdFormat::Transient],
    true,
);

$cases = [];
foreach ([
    'the AuthnRequest of for-bindings to this package, 978 bytes' => [
        'simplesamlphp-2.5.3.1-sp-authnrequest-to-bindings-query-2026-10-01.txt',
        'simplesamlphp-2.5.3.1-sp-metadata-for-bindings-2026-10-01.xml',
        '2026-10-01T11:03:34Z',
        null,
        'http://localhost:8093/bindings/idp/sso',
    ],
    'the AuthnRequest of default-sp to its identity provider, 986 bytes' => [
        'simplesamlphp-2.5.3.1-sp-authnrequest-query-2026-10-01.txt',
        'simplesamlphp-2.5.3.1-sp-metadata-default-sp-2026-10-01.xml',
        '2026-10-01T11:03:33Z',
        'simplesamlphp-2.5.3.1-idp-metadata-2026-10-01.xml',
        'http://localhost:8091/simplesaml/module.php/saml/idp/singleSignOnService',
    ],
] as $name => [$file, $spMetadata, $capturedAt, $idpMetadata, $receivedAt]) {
    $clock = new FrozenClock(new DateTimeImmutable($capturedAt));
    $sp = $metadata($spMetadata, $clock)->serviceProvider ?? throw new LogicException('a service provider');
    $idp = $idpMetadata === null ? $bindingsIdp : ($metadata($idpMetadata, $clock)->identityProvider ?? throw new LogicException('an identity provider'));
    $query = (string) file_get_contents($real . $file);
    $cases[$name] = static function () use ($query, $clock, $sp, $idp, $receivedAt): void {
        $loader = SamlLoader::create();
        new RedirectReceiver($loader)->authnRequest($query)->validate(new AuthnRequestValidator($loader, $clock), $sp, $idp, $receivedAt);
    };
}
$clock = new FrozenClock(new DateTimeImmutable('2026-10-01T11:03:34Z'));
$idp = $metadata('simplesamlphp-2.5.3.1-idp-metadata-2026-10-01.xml', $clock)->identityProvider ?? throw new LogicException('an identity provider');
$fields = BrowserForm::parsed((string) file_get_contents($real . 'simplesamlphp-2.5.3.1-idp-response-to-bindings-form-2026-10-01.txt'));
$expected = ExpectedResponse::toRequest('_41f764b4e7b601cffe0491118060eff82e63b868', 'http://localhost:8093/bindings/sp/acs', 'http://localhost:8093/bindings/sp');
$cases['beside it, the response form to this package, its response and its assertion signed'] = static function () use ($fields, $clock, $idp, $expected): void {
    $loader = SamlLoader::create();
    new PostReceiver($loader)->response($fields)->validate(new ResponseValidator($loader, $clock, new InMemoryReplayGuard()), $idp, $expected);
};

printf("PHP %s, %s\n", PHP_VERSION, OPENSSL_VERSION_TEXT);
foreach ($cases as $name => $run) {
    $durations = [];
    foreach (range(1, 520) as $iteration) {
        $start = hrtime(true);
        $run();
        if ($iteration > 20) {
            $durations[] = (hrtime(true) - $start) / 1e6;
        }
    }
    sort($durations);
    printf(
        "%s: median %.2f ms, 95th percentile %.2f ms, over %d runs\n",
        $name,
        $durations[intdiv(count($durations), 2)],
        $durations[(int) floor(count($durations) * 0.95)],
        count($durations),
    );
}
