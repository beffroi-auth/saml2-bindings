<?php

declare(strict_types=1);

/*
 * The capture (README.md of this directory, section 3): a login and a logout of the client capture of realm sp through
 * its SAML identity provider "idp", the broker, against realm idp, both as realms/ configures them, played with curl and
 * one cookie jar as a browser would; every query string and form of the exchange is kept, bytes as received, once this
 * package has read it and the model has validated or refused it, so that no capture is kept that the package was not
 * given. saml2-model's capture.sh, at its commit 9c833c5, decoded what it kept by hand (perl's base64 and raw inflate);
 * here every line of the binding is this package's: RedirectReceiver for what HTTP-Redirect carries, PostReceiver for
 * the fields of a form, read from the page and encoded as a browser does.
 *
 * Kept, in received/ or, with --keep, in tests/Fixture/real/: both metadata as served; the broker's AuthnRequest and
 * LogoutRequest, their query strings, unsigned under its defaults and refused by the model (saml2-model's findings 1 and
 * 2); realm idp's response and LogoutResponse, the bodies a browser posts from its forms. One line per step; the exit
 * status is 1 when a step fails.
 *
 * From the root of the repository, the installation up (castor keycloak --capture runs it):
 *   docker run --rm --init --network container:$(docker compose -f tests/Interop/keycloak/compose.yaml ps -q keycloak) \
 *       -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/keycloak/capture.php [--keep]
 */

use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\Exception\RefusedXml;

require __DIR__ . '/harness.php';

const REALM_IDP_SAML = KEYCLOAK . '/realms/idp/protocol/saml';
const BROKER_ENDPOINT = KEYCLOAK . '/realms/sp/broker/idp/endpoint';

$run = keycloak_run($argv);
$clock = new SystemClock();
wait_for_keycloak();

/**
 * The ID of a message the model refused, read to pair the answer with it: what the harness, an observer between two
 * Keycloaks, reads of the unverified document, never what the package or the model decides on.
 */
$messageId = static fn (Document $document): string => (string) $document->root()->getAttribute('ID');

/**
 * Both metadata, as served, kept, and read as the model reads metadata a channel vouches for.
 *
 * @return array{IdentityProvider, ServiceProvider}
 */
$metadata = static function () use ($run, $clock): array {
    $reader = new MetadataReader(SamlLoader::create(), $clock);
    $idp = new Browser()->get(KEYCLOAK . '/realms/idp/protocol/saml/descriptor');
    if ($idp->status !== 200) {
        throw new RuntimeException(sprintf('the metadata of realm idp: HTTP %d', $idp->status));
    }
    $run->keep('idp-metadata', $idp->body, 'xml');
    $sp = new Browser()->get(BROKER_ENDPOINT . '/descriptor');
    if ($sp->status !== 200) {
        throw new RuntimeException(sprintf('the metadata of the broker: HTTP %d', $sp->status));
    }
    $run->keep('sp-metadata', $sp->body, 'xml');

    return [
        $reader->readTrusted(SamlLoader::create()->load($idp->body))->identityProvider
            ?? throw new RuntimeException('the metadata of realm idp holds no identity provider'),
        $reader->readTrusted(SamlLoader::create()->load($sp->body))->serviceProvider
            ?? throw new RuntimeException('the metadata of the broker holds no service provider'),
    ];
};

$parties = $run->step('both metadata, as served', $metadata);
if (! is_array($parties)) {
    $run->exit();
}
[$idp, $sp] = $parties;

$login = $run->step('login: the broker\'s AuthnRequest, realm idp\'s response', static function () use ($run, $clock, $idp, $sp, $messageId): array {
    $browser = new Browser();
    $url = $browser->get(client_login('idp'))->followWithin(KEYCLOAK . '/realms/sp/')
        ->redirect('a redirect to the single sign-on service of realm idp');
    [$endpoint, $query] = split_url($url);
    if ($endpoint !== REALM_IDP_SAML) {
        throw new RuntimeException(sprintf('the broker sent to %s', $endpoint));
    }
    $run->keep('sp-authnrequest-unsigned-refused-query', $query);
    $request = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
    $run->say(sprintf('RedirectReceiver read its AuthnRequest; its query string, %s; RelayState of %d bytes', query_described($query), strlen((string) $request->relayState)));
    try {
        $request->validate(new AuthnRequestValidator(SamlLoader::create(), $clock), $sp, $idp, $endpoint);
    } catch (RefusedXml $refused) {
        $run->say(sprintf('the model refused it: %s: %s', $refused::class, $refused->getMessage()));
    }
    if (! isset($refused)) {
        throw new RuntimeException('the model accepted the AuthnRequest of the broker under its defaults');
    }

    $form = log_in($browser->get($url))->form('form of the response');
    if ($form->action !== BROKER_ENDPOINT) {
        throw new RuntimeException(sprintf('realm idp posts its response to %s', $form->action));
    }
    $body = $form->body();
    $run->keep('idp-response-form', $body);
    $response = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed($body));
    $accepted = $response->validate(
        new ResponseValidator(SamlLoader::create(), $clock, new InMemoryReplayGuard()),
        $idp,
        ExpectedResponse::toRequest($messageId($request->request->document), BROKER_ENDPOINT, $sp->entityId),
    );
    $run->say(sprintf(
        'its form posts the fields %s, SAMLResponse of %d characters, %s; PostReceiver read and the model accepted the response %s (%s), the RelayState returned as sent',
        implode(', ', $form->names()),
        strlen((string) $form->field('SAMLResponse')),
        $form->wrapped('SAMLResponse') ? 'WRAPPED' : 'on one line',
        $accepted->responseId,
        $accepted->coverage->name,
    ));
    if ($response->relayState !== $request->relayState) {
        throw new RuntimeException('realm idp did not echo the RelayState of the broker');
    }
    $returned = $browser->submit($form)->followWithin(KEYCLOAK . '/realms/')->redirect('a redirect to the client capture');
    if (! str_starts_with($returned, CLIENT_REDIRECT)) {
        throw new RuntimeException(sprintf('the broker sent to %s', $returned));
    }
    $tokens = client_tokens($browser, $returned);
    $run->say('the broker accepted it, and the client capture of realm sp got its tokens');

    return [$browser, $tokens];
});

if (is_array($login)) {
    $run->step('logout: the broker\'s LogoutRequest, realm idp\'s LogoutResponse', static function () use ($run, $clock, $idp, $sp, $login, $messageId): void {
        [$browser, $tokens] = $login;
        $url = $browser->get(client_logout((string) $tokens['id_token']))->followWithin(KEYCLOAK . '/realms/sp/')
            ->redirect('a redirect to the single logout service of realm idp');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== REALM_IDP_SAML) {
            throw new RuntimeException(sprintf('the broker sent to %s', $endpoint));
        }
        $run->keep('sp-logoutrequest-unsigned-refused-query', $query);
        $request = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
        if (! $request instanceof ReceivedLogoutRequest) {
            throw new RuntimeException('the broker sent no LogoutRequest');
        }
        $run->say(sprintf('RedirectReceiver read its LogoutRequest; its query string, %s; RelayState of %d bytes', query_described($query), strlen((string) $request->relayState)));
        try {
            $request->validate(new LogoutRequestValidator(SamlLoader::create(), $clock), $sp, $idp, $endpoint);
        } catch (RefusedXml $refused) {
            $run->say(sprintf('the model refused it: %s: %s', $refused::class, $refused->getMessage()));
        }
        if (! isset($refused)) {
            throw new RuntimeException('the model accepted the unsigned LogoutRequest of the broker');
        }

        $browser->get($url)->followWithin(KEYCLOAK . '/realms/idp/');
        if (! post_binding_page($browser)) {
            throw new RuntimeException(sprintf('realm idp answered the LogoutRequest with no form: HTTP %d%s', $browser->status, $browser->error()));
        }
        $form = $browser->form('form of the LogoutResponse');
        if ($form->action !== BROKER_ENDPOINT) {
            throw new RuntimeException(sprintf('realm idp posts its LogoutResponse to %s', $form->action));
        }
        $body = $form->body();
        $run->keep('idp-logoutresponse-form', $body);
        $response = new PostReceiver(SamlLoader::create())->logoutMessage(BrowserForm::parsed($body));
        if (! $response instanceof ReceivedLogoutResponse) {
            throw new RuntimeException('realm idp answered with no LogoutResponse');
        }
        $accepted = $response->validate(
            new LogoutResponseValidator(SamlLoader::create(), $clock),
            $idp,
            $sp,
            BROKER_ENDPOINT,
            $messageId($request->request->document),
        );
        $run->say(sprintf(
            'its form posts the fields %s, SAMLResponse of %d characters, %s; PostReceiver read and the model accepted the LogoutResponse %s (%s), status %s',
            implode(', ', $form->names()),
            strlen((string) $form->field('SAMLResponse')),
            $form->wrapped('SAMLResponse') ? 'WRAPPED' : 'on one line',
            $accepted->response->id,
            $accepted->authentication->name,
            $accepted->response->status->code->name,
        ));
        $returned = $browser->submit($form)->followWithin(KEYCLOAK . '/realms/')->redirect('a redirect to the client capture');
        if (! str_starts_with($returned, CLIENT_REDIRECT)) {
            throw new RuntimeException(sprintf('the broker sent to %s', $returned));
        }
        $run->say('the broker accepted it, and the client capture of realm sp is logged out');
    });
}

$run->exit();
