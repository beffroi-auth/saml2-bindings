<?php

declare(strict_types=1);

/*
 * The capture (README.md of this directory, section 3): a login and a logout started by SimpleSAMLphp's service
 * provider default-sp against SimpleSAMLphp's identity provider, both as the installation configures them, played
 * with curl and one cookie jar as a browser would; every query string and form of the exchange is kept, bytes as
 * received, once this package has read it and the model has validated it, so that no capture is kept that the package
 * was not given. saml2-model's installation/capture.sh, at its commit 9c833c5, decoded and verified what it kept by
 * hand inside the identity provider's container (gzinflate(), base64_decode(), openssl_verify() over octets it built);
 * here every line of the binding is this package's: RedirectReceiver for what HTTP-Redirect carries, PostReceiver for
 * the fields of a form, read from the page and encoded as a browser does.
 *
 * Kept, in received/ or, with --keep, in tests/Fixture/real/: both metadata as served; default-sp's signed AuthnRequest
 * and LogoutRequest, their query strings; the identity provider's response, the body a browser posts from its form; its
 * LogoutResponse, the query string, unsigned under SimpleSAMLphp's defaults and refused by the model (SignatureRequired,
 * M-2; saml2-model's finding F-1). One line per step; the exit status is 1 when a step fails.
 *
 * From the root of the repository, the installation up (castor simplesamlphp --capture runs it):
 *   docker run --rm --network saml2-bindings-simplesamlphp_default \
 *       -e EXCHANGE_CONNECT_TO=localhost:8091:idp:80,localhost:8092:sp:80 -v "$PWD:/project" -w /project \
 *       ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/capture.php [--keep]
 */

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;

require __DIR__ . '/harness.php';

const DEFAULT_SP = SP . '/module.php/saml/sp/metadata/default-sp';
const RETURN_TO = SP . '/module.php/core/welcome';

$run = new Run(in_array('--keep', $argv, true) ? __DIR__ . '/../../Fixture/real' : __DIR__ . '/received');
$clock = new SystemClock();

/**
 * Both metadata, as served, kept, and read as the model reads metadata a channel vouches for.
 *
 * @return array{IdentityProvider, ServiceProvider}
 */
$metadata = static function () use ($run, $clock): array {
    $browser = new Browser();
    $reader = new MetadataReader(SamlLoader::create(), $clock);
    $idp = $browser->get(IDP . '/module.php/saml/idp/metadata');
    if ($idp->status !== 200) {
        throw new RuntimeException(sprintf('the metadata of the identity provider: HTTP %d', $idp->status));
    }
    $run->keep('idp-metadata', $idp->body, 'xml');
    $identityProvider = $reader->readTrusted(SamlLoader::create()->load($idp->body))->identityProvider
        ?? throw new RuntimeException('the metadata of the identity provider holds no identity provider');
    $sp = $browser->get(DEFAULT_SP);
    if ($sp->status !== 200) {
        throw new RuntimeException(sprintf('the metadata of default-sp: HTTP %d', $sp->status));
    }
    $run->keep('sp-metadata-default-sp', $sp->body, 'xml');
    $serviceProvider = $reader->readTrusted(SamlLoader::create()->load($sp->body))->serviceProvider
        ?? throw new RuntimeException('the metadata of default-sp holds no service provider');

    return [$identityProvider, $serviceProvider];
};

$roles = $run->step('the metadata of both parties, as served', $metadata);
if (! is_array($roles)) {
    $run->exit();
}
[$idp, $sp] = $roles;
$sso = IDP . '/module.php/saml/idp/singleSignOnService';
$slo = IDP . '/module.php/saml/idp/singleLogout';
$browser = new Browser();

$login = $run->step(
    'login, from default-sp to the identity provider',
    static function () use ($run, $clock, $browser, $idp, $sp, $sso): bool {
        $url = $browser->get(SP . '/module.php/saml/sp/login/default-sp?ReturnTo=' . rawurlencode(RETURN_TO))
            ->redirect('a redirect to the single sign-on service');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== $sso) {
            throw new RuntimeException(sprintf('default-sp sent to %s', $endpoint));
        }
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
        $accepted = $received->validate(new AuthnRequestValidator(SamlLoader::create(), $clock), $sp, $idp, $sso);
        $run->keep('sp-authnrequest-query', $query);
        $run->say(sprintf(
            'RedirectReceiver verified and the model accepted the AuthnRequest %s of default-sp (%s), issued %s, RelayState %d bytes',
            $accepted->request->id,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
            strlen((string) $received->relayState),
        ));

        $form = $browser->get($url)->followWithin(IDP . '/')->logIn()->form('form of the response');
        $body = $form->body();
        $response = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed($body));
        $assertion = $response->validate(
            new ResponseValidator(SamlLoader::create(), $clock, new InMemoryReplayGuard()),
            $idp,
            ExpectedResponse::toRequest($accepted->request->id, $form->action, DEFAULT_SP),
        );
        $run->keep('idp-response-form', $body);
        $run->say(sprintf(
            'PostReceiver read and the model accepted the response %s (%s), fields %s, RelayState %s',
            $assertion->responseId,
            $assertion->coverage->name,
            implode(', ', $form->names()),
            $response->relayState === RETURN_TO ? 'the ReturnTo echoed' : var_export($response->relayState, true),
        ));

        $returned = $browser->submit($form)->redirect('a redirect from the assertion consumer service');
        if ($returned !== RETURN_TO) {
            throw new RuntimeException(sprintf('the assertion consumer service sent to %s', $returned));
        }
        $run->say('default-sp accepted the response and returned to its ReturnTo');

        return true;
    },
);

if ($login === true) {
    $run->step(
        'logout, from default-sp to the identity provider and back',
        static function () use ($run, $clock, $browser, $idp, $sp, $slo): void {
            $url = $browser->get(SP . '/module.php/core/logout/default-sp?ReturnTo=' . rawurlencode(RETURN_TO))
                ->redirect('a redirect to the single logout service');
            [$endpoint, $query] = split_url($url);
            if ($endpoint !== $slo) {
                throw new RuntimeException(sprintf('default-sp sent to %s', $endpoint));
            }
            $received = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
            if (! $received instanceof ReceivedLogoutRequest) {
                throw new RuntimeException('default-sp sent no LogoutRequest');
            }
            $request = $received->validate(new LogoutRequestValidator(SamlLoader::create(), $clock), $sp, $idp, $slo);
            $run->keep('sp-logoutrequest-query', $query);
            $run->say(sprintf(
                'RedirectReceiver verified and the model accepted the LogoutRequest %s of default-sp (%s), issued %s, RelayState %d bytes',
                $request->request->id,
                $request->authentication->name,
                $request->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
                strlen((string) $received->relayState),
            ));

            $url = $browser->get($url)->redirect('a redirect from the single logout service');
            while (str_starts_with($url, IDP . '/')) {
                $url = $browser->get($url)->redirect($url);
            }
            [$endpoint, $query] = split_url($url);
            $spSlo = SP . '/module.php/saml/sp/saml2-logout.php/default-sp';
            if ($endpoint !== $spSlo) {
                throw new RuntimeException(sprintf('the identity provider answered to %s', $endpoint));
            }
            $answer = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
            if (! $answer instanceof ReceivedLogoutResponse) {
                throw new RuntimeException('the identity provider answered with no LogoutResponse');
            }
            try {
                $answer->validate(new LogoutResponseValidator(SamlLoader::create(), $clock), $idp, $sp, $spSlo, $request->request->id);
                throw new RuntimeException('the model accepted an unsigned LogoutResponse');
            } catch (SignatureRequired $refused) {
                $run->keep('idp-logoutresponse-unsigned-refused-query', $query);
                $run->say(sprintf(
                    'RedirectReceiver read the LogoutResponse %s unsigned, which validate() refused: %s',
                    $answer->response->issuer ?? 'without issuer',
                    $refused->getMessage(),
                ));
            }

            $returned = $browser->get($url)->redirect('a redirect from the single logout service of default-sp');
            if ($returned !== RETURN_TO) {
                throw new RuntimeException(sprintf('default-sp sent to %s', $returned));
            }
            $run->say('default-sp accepted the unsigned LogoutResponse, closed its session and returned to its ReturnTo');
        },
    );
}

$run->exit();
