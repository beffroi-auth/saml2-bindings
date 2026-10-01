<?php

declare(strict_types=1);

/*
 * The exchange (README.md of this directory, section 4): this package and Keycloak's two realms, both ways, login and
 * logout, over HTTP-Redirect wherever Keycloak allows it, then the probes and the measures of section 9.5 of
 * spec/bindings.md, on the running installation, with the package of the repository (its vendor/autoload.php), the test
 * keys of tests/Fixture/keys/ and the live clock.
 *
 * Keycloak is configured from the metadata of this package's two roles, written by the model's MetadataWriter, by its
 * own importers through the admin REST API: realm sp's identity provider "bindings" by import-config, realm idp's SAML
 * client by client-description-converter, as an administrator who imports a metadata file in the console. The script
 * is the browser and the HTTP layer of this package's roles, which answer at https://idp.saml2-bindings.test/ and
 * https://sp.saml2-bindings.test/ where nothing listens: it reads what Keycloak sends there and answers. It is
 * saml2-model's exchange.php, at its commit 9c833c5, which posted every message and left HTTP-Redirect to this package,
 * with every line that played the binding replaced by this package: RedirectSender writes every URL this package sends,
 * PostSender every form, RedirectReceiver reads every query string Keycloak sends and PostReceiver every form, read from
 * the page by the harness (../harness.php) and encoded as a browser does. No gzinflate(), no base64_decode(), no
 * http_build_query() and no octets built by hand, except where a measure needs what the package refuses to write (an
 * RSA-SHA1 signature, a SigAlg off its list, a "+" in a signed RelayState): those are built by signed_by_hand() of
 * ../harness.php, named so, and sent for the measure only.
 *
 * What Keycloak sent goes to received/, or to tests/Fixture/real/ with --keep, named with its version and the date;
 * the metadata of this package's roles, as given to Keycloak, to written/. One line per step and per measure; the exit
 * status is 1 when a step fails.
 *
 * From the root of the repository, the installation up (castor keycloak runs it all):
 *   docker run --rm --init --network container:$(docker compose -f tests/Interop/keycloak/compose.yaml ps -q keycloak) \
 *       -v "$PWD:/project" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/keycloak/exchange.php [--keep]
 */

use Beffroi\Saml2\Bindings\PostForm;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\ReceivedLogoutRequest;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Bindings\Tests\Support\BrowserForm;
use Beffroi\Saml2\Bindings\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Assertion\Assertion;
use Beffroi\Saml2\Model\Assertion\Attribute;
use Beffroi\Saml2\Model\Assertion\AttributeNameFormat;
use Beffroi\Saml2\Model\Assertion\AuthnStatement;
use Beffroi\Saml2\Model\Assertion\Conditions;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Assertion\SubjectConfirmation;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\Protocol\Response;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutRequestValidator;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;

require __DIR__ . '/harness.php';

// This package's two roles. Nothing answers at these URLs: the script reads what Keycloak sends there and answers.
const BINDINGS_IDP = 'https://idp.saml2-bindings.test/metadata';
const BINDINGS_SSO = 'https://idp.saml2-bindings.test/sso';
const BINDINGS_IDP_SLO = 'https://idp.saml2-bindings.test/slo';
const BINDINGS_SP = 'https://sp.saml2-bindings.test/metadata';
const BINDINGS_ACS = 'https://sp.saml2-bindings.test/acs';
const BINDINGS_SP_SLO = 'https://sp.saml2-bindings.test/slo';
// Realm sp's identity provider facing this package, and the subject this package's identity provider asserts to it: a
// name no login of realms/idp.json can give realm sp's users.
const BROKER = 'bindings';
const SUBJECT = 'bindings-alice';
// The settings of the admin console's form that import-config does not return (SamlGeneralSettings-*.js of Keycloak
// 26.7.4, as saml2-model's README reads them): what an administrator who imports the metadata in the console gets.
const CONSOLE_DEFAULTS = [
    'entityId' => KEYCLOAK . '/realms/sp',
    'wantAssertionsSigned' => 'true',
    'nameIDPolicyFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'principalType' => 'SUBJECT',
    'allowCreate' => 'true',
    'allowedClockSkew' => '0',
    'attributeConsumingServiceIndex' => '0',
];
const FIRST_BROKER_LOGIN = 'first broker login without review profile';
// The settings import-config draws from the identity provider metadata that decide the bindings and the signatures.
const IMPORTED_BINDINGS = ['postBindingAuthnRequest', 'postBindingResponse', 'postBindingLogout', 'wantAuthnRequestsSigned'];

final class Exchange
{
    private readonly SystemClock $clock;

    /**
     * The captures already kept in this run, by name: each is kept once, the first time it is seen.
     *
     * @var array<string, true>
     */
    private array $kept = [];

    public function __construct(
        private readonly Run $run,
        private readonly string $written,
        private readonly string $keys,
    ) {
        $this->clock = new SystemClock();
    }

    /**
     * This package's identity provider: HTTP-Redirect for its single sign-on and single logout services, HTTP-POST
     * after them when $post, wanting its requests signed.
     */
    public function identityProvider(bool $post = false): IdentityProvider
    {
        return new IdentityProvider(
            BINDINGS_IDP,
            [$this->certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, BINDINGS_SSO), ...($post ? [new Endpoint(Binding::HttpPost, BINDINGS_SSO)] : [])],
            [new Endpoint(Binding::HttpRedirect, BINDINGS_IDP_SLO), ...($post ? [new Endpoint(Binding::HttpPost, BINDINGS_IDP_SLO)] : [])],
            [NameIdFormat::Persistent],
            wantAuthnRequestsSigned: true,
        );
    }

    /**
     * This package's service provider: its assertion consumer service over HTTP-POST, its single logout service over
     * HTTP-Redirect and HTTP-POST, so that the converter sets both logout URLs of the client; signing its requests, and
     * wanting its assertions signed no more than the model's harness did, realm idp signing the response by default.
     */
    public function serviceProvider(): ServiceProvider
    {
        return new ServiceProvider(
            BINDINGS_SP,
            [$this->certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, BINDINGS_ACS, 0, true)]),
            [new Endpoint(Binding::HttpRedirect, BINDINGS_SP_SLO), new Endpoint(Binding::HttpPost, BINDINGS_SP_SLO)],
            [NameIdFormat::Persistent],
            authnRequestsSigned: true,
            wantAssertionsSigned: false,
        );
    }

    /**
     * Keycloak configured from this package's metadata by its own importers, after the measure of what import-config
     * draws from an identity provider metadata listing HTTP-Redirect alone, and HTTP-Redirect then HTTP-POST
     * (saml2-model's finding 17); then realm idp's metadata, read live and kept.
     */
    public function configure(Admin $admin): IdentityProvider
    {
        $redirect = $this->metadata('bindings-idp-metadata', new EntityDescriptor(BINDINGS_IDP, identityProvider: $this->identityProvider()), 'idp');
        $both = $this->metadata('bindings-idp-both-bindings-metadata', new EntityDescriptor(BINDINGS_IDP, identityProvider: $this->identityProvider(true)), 'idp');
        $sp = $this->metadata('bindings-sp-metadata', new EntityDescriptor(BINDINGS_SP, serviceProvider: $this->serviceProvider()), 'sp');

        $importConfig = '/admin/realms/sp/identity-provider/import-config';
        $listed = $admin->upload($importConfig, $both, 'application/xml', 'file', ['providerId' => 'saml']);
        $this->run->say('import-config, this package\'s identity provider metadata listing HTTP-Redirect then HTTP-POST: '
            . settings(array_intersect_key($listed, array_flip(IMPORTED_BINDINGS))));
        $imported = $admin->upload($importConfig, $redirect, 'application/xml', 'file', ['providerId' => 'saml']);
        $this->run->say('import-config, the same listing HTTP-Redirect alone, what the broker is created from: ' . settings($imported));

        // A run on a live container starts from nothing: the identity provider, the user the subject became in realm
        // sp on an earlier run (deleting the identity provider keeps it, and the first broker login would ask to link
        // it), and the client of realm idp.
        $admin->call('DELETE', '/admin/realms/sp/identity-provider/instances/' . BROKER, expect: [204, 404]);
        foreach ($admin->json('GET', '/admin/realms/sp/users?exact=true&username=' . rawurlencode(SUBJECT)) as $user) {
            $admin->call('DELETE', '/admin/realms/sp/users/' . $user['id']);
        }
        $admin->call('POST', '/admin/realms/sp/identity-provider/instances', [
            'alias' => BROKER,
            'providerId' => 'saml',
            'enabled' => true,
            'firstBrokerLoginFlowAlias' => FIRST_BROKER_LOGIN,
            'config' => array_merge(CONSOLE_DEFAULTS, $imported),
        ], [201]);
        foreach ($admin->json('GET', '/admin/realms/idp/clients?clientId=' . rawurlencode(BINDINGS_SP)) as $client) {
            $admin->call('DELETE', '/admin/realms/idp/clients/' . $client['id']);
        }
        $description = $admin->upload('/admin/realms/idp/client-description-converter', $sp, 'application/xml');
        $admin->call('POST', '/admin/realms/idp/clients', $description, [201]);
        $client = $admin->json('GET', '/admin/realms/idp/clients?clientId=' . rawurlencode(BINDINGS_SP))[0] ?? [];
        $this->run->say(sprintf(
            'realm idp, client %s from client-description-converter, the server\'s defaults added: %s; frontchannelLogout=%s',
            BINDINGS_SP,
            settings($client['attributes'] ?? []),
            var_export($client['frontchannelLogout'] ?? null, true),
        ));

        $realmIdp = $this->read('/realms/idp/protocol/saml/descriptor', 'idp-metadata')->identityProvider
            ?? throw new RuntimeException('realm idp publishes no identity provider');
        $this->run->say(sprintf(
            'realm idp\'s metadata, read by MetadataReader::readTrusted(): %d signing certificate, single sign-on services %s, single logout services %s',
            count($realmIdp->signingCertificates),
            self::bindings($realmIdp->singleSignOnServices),
            self::bindings($realmIdp->singleLogoutServices),
        ));

        return $realmIdp;
    }

    /**
     * The metadata of realm sp's identity provider facing this package, the broker as a service provider, read live and
     * kept as $keep the first time: read as import-config set the broker, then again once its "HTTP-POST binding
     * response" is switched on, which changes nothing in it but its ID (measured on 1 October 2026).
     */
    public function broker(string $keep): ServiceProvider
    {
        $broker = $this->read('/realms/sp/broker/' . BROKER . '/endpoint/descriptor', $keep)->serviceProvider
            ?? throw new RuntimeException('the broker publishes no service provider');
        $this->run->say(sprintf(
            'the broker\'s metadata, read by MetadataReader::readTrusted(): %d signing certificate, AuthnRequestsSigned %s, WantAssertionsSigned %s, assertion consumer services kept %s, default index %d, single logout services %s',
            count($broker->signingCertificates),
            var_export($broker->authnRequestsSigned, true),
            var_export($broker->wantAssertionsSigned, true),
            implode(', ', array_map(
                static fn (IndexedEndpoint $endpoint): string => sprintf('%s index %d', $endpoint->binding->name, $endpoint->index),
                $broker->assertionConsumerServices->endpoints,
            )),
            $broker->assertionConsumerServices->default()->index,
            self::bindings($broker->singleLogoutServices),
        ));

        return $broker;
    }

    /**
     * One setting of realm sp's identity provider facing this package, changed as an administrator changes it in the
     * console.
     */
    public function brokerSetting(Admin $admin, string $name, string $value): void
    {
        $path = '/admin/realms/sp/identity-provider/instances/' . BROKER;
        $instance = $admin->json('GET', $path);
        $before = $instance['config'][$name] ?? 'absent';
        $instance['config'][$name] = $value;
        $admin->call('PUT', $path, $instance);
        $this->run->say(sprintf('realm sp, identity provider %s: %s from %s to %s', BROKER, $name, $before, $value));
    }

    /**
     * One attribute of realm idp's client for this package, changed as an administrator changes it in the console.
     */
    public function clientSetting(Admin $admin, string $name, string $value): void
    {
        $client = $admin->json('GET', '/admin/realms/idp/clients?clientId=' . rawurlencode(BINDINGS_SP))[0]
            ?? throw new RuntimeException('no client for this package in realm idp');
        $before = $client['attributes'][$name] ?? 'absent';
        // The attribute alone: Keycloak merges the attributes of an update into the client's, and the representation it
        // answered, decoded into PHP arrays, would go back with its empty objects turned into lists, which it refuses.
        $admin->call('PUT', '/admin/realms/idp/clients/' . $client['id'], [
            'id' => $client['id'],
            'clientId' => $client['clientId'],
            'attributes' => [$name => $value],
        ]);
        $after = $admin->json('GET', '/admin/realms/idp/clients/' . $client['id'])['attributes'][$name] ?? 'absent';
        if ($after !== $value) {
            throw new RuntimeException(sprintf('the client holds %s=%s', $name, $after));
        }
        $this->run->say(sprintf('realm idp, client %s: %s from %s to %s', BINDINGS_SP, $name, $before, $value));
    }

    /**
     * Direction 1, the broker as import-config set it, HTTP-Redirect for everything: its AuthnRequest, received by
     * RedirectReceiver, verified, then refused by the model, which answers no request asking for its response over
     * HTTP-Redirect (model.md section 8, saml2-model's finding 1).
     */
    public function brokerAsImported(): void
    {
        $broker = $this->broker('sp-metadata-for-bindings');
        $query = $this->brokerAuthnRequest(new Browser());
        $this->keep('sp-authnrequest-to-bindings-redirect-binding-refused-query', $query);
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
        $this->run->say(sprintf('its query string, %s; RelayState of %d bytes', query_described($query), strlen((string) $received->relayState)));
        try {
            $received->validate(new AuthnRequestValidator(SamlLoader::create(), $this->clock), $broker, $this->identityProvider(), BINDINGS_SSO);
        } catch (Unsupported $refused) {
            $this->run->say(sprintf(
                'RedirectReceiver verified its signature, and the model refused it after the binding\'s authentication: %s: %s',
                $refused::class,
                $refused->getMessage(),
            ));

            return;
        }

        throw new RuntimeException('the model accepted an AuthnRequest asking for its response over HTTP-Redirect');
    }

    /**
     * Direction 1, login: this package as an identity provider, realm sp's broker in front. Its AuthnRequest, over
     * HTTP-Redirect signed, received by RedirectReceiver and validated by the model (Authentication::Binding); the
     * model's response, its assertion signed (the broker wants it so), posted through PostSender's form to the broker's
     * assertion consumer service; the first broker login creates the user and the client capture gets its code.
     *
     * @return array{Browser, array<string, mixed>, Assertion}
     */
    public function loginAtThePackage(ServiceProvider $broker): array
    {
        $browser = new Browser();
        $query = $this->brokerAuthnRequest($browser);
        $this->keep('sp-authnrequest-to-bindings-query', $query);
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
        $accepted = $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), $this->clock),
            $broker,
            $this->identityProvider(),
            BINDINGS_SSO,
        );
        $this->run->say(sprintf(
            'RedirectReceiver verified and the model accepted the AuthnRequest %s of the broker (%s), issued %s; its query string, %s; RelayState of %d bytes; ProtocolBinding %s; its assertion consumer service %s, index %s',
            $accepted->request->id,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s.v\Z'),
            query_described($query),
            strlen((string) $received->relayState),
            $accepted->request->protocolBinding ?? 'absent',
            $accepted->assertionConsumerService->location,
            $accepted->assertionConsumerService->index,
        ));

        $response = $this->responseTo($accepted, $broker);
        $assertion = $response->assertion ?? throw new LogicException('the response carries its assertion');
        $form = new PostSender()->response($response, $this->signing('idp'), SignedParts::Assertion, $received->relayState);
        $returned = $this->submit($browser, $form)->followWithin(KEYCLOAK . '/realms/')
            ->redirect('a redirect to the client capture, the response accepted');
        if (! str_starts_with($returned, CLIENT_REDIRECT)) {
            throw new RuntimeException(sprintf('the broker sent to %s', $returned));
        }
        $tokens = client_tokens($browser, $returned);
        $claims = client_userinfo((string) $tokens['access_token']) ?? throw new RuntimeException('realm sp holds no session');
        if (($claims['preferred_username'] ?? null) !== SUBJECT) {
            throw new RuntimeException(sprintf('realm sp logged in %s', json_encode($claims)));
        }
        $this->run->say(sprintf(
            'the broker accepted the response %s (SignedParts::Assertion), posted through PostSender\'s form with the RelayState it sent, and realm sp logged in %s',
            $response->id,
            SUBJECT,
        ));

        return [$browser, $tokens, $assertion];
    }

    /**
     * Direction 1, logout: the client's session ended at realm sp, the broker's LogoutRequest, over HTTP-Redirect
     * signed, received by RedirectReceiver and validated by the model; this package's LogoutResponse, sent by
     * RedirectSender signed to the broker's single logout service for HTTP-Redirect, first changed after signing (the
     * probes of section 9.5 point 3, each of which the broker must refuse), then as sent, which ends at the client.
     *
     * @param array<string, mixed> $tokens
     */
    public function logoutAtThePackage(Browser $browser, array $tokens, Assertion $assertion, ServiceProvider $broker): void
    {
        $url = $browser->get(client_logout((string) $tokens['id_token']))->followWithin(KEYCLOAK . '/realms/sp/')
            ->redirect('a redirect to the single logout service of this package');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== BINDINGS_IDP_SLO) {
            throw new RuntimeException(sprintf('the broker sent to %s', $endpoint));
        }
        $this->keep('sp-logoutrequest-to-bindings-query', $query);
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new RuntimeException('the broker sent no LogoutRequest');
        }
        $accepted = $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), $this->clock),
            $broker,
            $this->identityProvider(),
            BINDINGS_IDP_SLO,
        );
        $this->run->say(sprintf(
            'RedirectReceiver verified and the model accepted the LogoutRequest %s of the broker (%s); its query string, %s; RelayState of %d bytes',
            $accepted->request->id,
            $accepted->authentication->name,
            query_described($query),
            strlen((string) $received->relayState),
        ));
        if (
            $accepted->request->nameId->value !== $assertion->nameId->value
            || $accepted->request->sessionIndexes !== [$assertion->authnStatement->sessionIndex]
        ) {
            throw new RuntimeException('the LogoutRequest names another session than the one this package opened');
        }

        $sender = new RedirectSender();
        $answer = $sender->logoutResponse($this->logoutResponseTo($accepted->request, $broker), $this->signing('idp'), $received->relayState);
        $other = $sender->logoutResponse($this->logoutResponseTo($accepted->request, $broker), $this->signing('idp'), $received->relayState);
        foreach (query_tampered($answer, $other, 'SAMLResponse') as $what => $tampered) {
            $this->refused($browser->get($tampered), 'the broker, a LogoutResponse ' . $what);
        }
        $returned = $browser->get($answer)->followWithin(KEYCLOAK . '/realms/')
            ->redirect('a redirect to the client capture, the LogoutResponse accepted');
        if (! str_starts_with($returned, CLIENT_REDIRECT)) {
            throw new RuntimeException(sprintf('the broker sent to %s', $returned));
        }
        if (client_userinfo((string) $tokens['access_token']) !== null) {
            throw new RuntimeException('the session of realm sp is still open');
        }
        $this->run->say('the broker accepted the LogoutResponse of this package, signed by RedirectSender over HTTP-Redirect, and realm sp closed its session');
    }

    /**
     * Measure: the RelayState of the broker's AuthnRequest for a client of realm sp whose internal ID is not a UUID,
     * which Keycloak then writes as the base64url of its client_id (IdentityBrokerState.decoded() of 26.7.4), and what
     * RedirectReceiver does of it.
     */
    public function measureBrokerRelayState(Admin $admin, string $clientId): void
    {
        $internalId = 'bindings-measure-client';
        $admin->call('DELETE', '/admin/realms/sp/clients/' . $internalId, expect: [204, 404]);
        $admin->call('POST', '/admin/realms/sp/clients', [
            'id' => $internalId,
            'clientId' => $clientId,
            'protocol' => 'openid-connect',
            'publicClient' => true,
            'standardFlowEnabled' => true,
            'redirectUris' => [CLIENT_REDIRECT],
        ], [201]);
        $client = $admin->json('GET', '/admin/realms/sp/clients?clientId=' . rawurlencode($clientId))[0] ?? [];
        $query = $this->brokerAuthnRequest(new Browser(), $clientId);
        $raw = query_value($query, 'RelayState');
        try {
            new RedirectReceiver(SamlLoader::create())->authnRequest($query);
            $outcome = 'RedirectReceiver read it';
        } catch (Throwable $refused) {
            $outcome = sprintf('RedirectReceiver refused it: %s: %s', $refused::class, $refused->getMessage());
            $this->keep('sp-authnrequest-to-bindings-long-relaystate-refused-query', $query);
        }
        $this->run->say(sprintf(
            'the broker, for the client %s of %d bytes, its internal ID %s: RelayState %s; %s',
            $clientId,
            strlen($clientId),
            var_export($client['id'] ?? null, true),
            $raw === null ? 'absent' : sprintf('%s, %d bytes', $raw, strlen(urldecode($raw))),
            $outcome,
        ));
        $admin->call('DELETE', '/admin/realms/sp/clients/' . $internalId);
    }

    /**
     * Direction 2, login: this package as a service provider, realm idp in front. The model's AuthnRequest, sent by
     * RedirectSender signed to realm idp's single sign-on service for HTTP-Redirect, which verifies it and shows its
     * login page; the test user's login; the response read from the form of the page, posted as a browser posts it,
     * received by PostReceiver and validated by the model.
     *
     * @return array{Browser, AcceptedAssertion}
     */
    public function loginAtKeycloak(IdentityProvider $realmIdp, ?string $relayState): array
    {
        $browser = new Browser();
        $request = $this->authnRequestTo($realmIdp);
        $url = new RedirectSender()->authnRequest($request, $this->signing('sp'), $relayState);
        if (! login_page($browser->get($url))) {
            throw new RuntimeException(sprintf('realm idp did not show its login page: HTTP %d%s', $browser->status, $browser->error()));
        }
        $this->run->say(sprintf(
            'realm idp verified the AuthnRequest %s, its query string of %d bytes signed by RedirectSender, and showed its login page',
            $request->id,
            strlen(split_url($url)[1]),
        ));

        $form = log_in($browser)->form('form of the response');
        $this->run->say(sprintf(
            'its form posts to %s the fields %s; SAMLResponse of %d characters, %s; RelayState %s',
            $form->action,
            implode(', ', $form->names()),
            strlen((string) $form->field('SAMLResponse')),
            $form->wrapped('SAMLResponse') ? 'WRAPPED' : 'on one line',
            relay_state_of($form->field('RelayState'), $relayState),
        ));
        if ($form->action !== BINDINGS_ACS) {
            throw new RuntimeException(sprintf('realm idp posts its response to %s', $form->action));
        }
        $body = $form->body();
        $this->keep('idp-response-to-bindings-form', $body);
        $received = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed($body));
        if ($received->relayState !== $relayState) {
            throw new RuntimeException('PostReceiver returned another RelayState than the one sent');
        }
        $accepted = $received->validate(
            new ResponseValidator(SamlLoader::create(), $this->clock, new InMemoryReplayGuard()),
            $realmIdp,
            ExpectedResponse::toRequest($request->id, BINDINGS_ACS, BINDINGS_SP),
        );
        $this->run->say(sprintf(
            'PostReceiver read and the model accepted the response %s (%s), issued %s, NameID %s (%s), %d attributes',
            $accepted->responseId,
            $accepted->coverage->name,
            $accepted->assertion->issueInstant->format('Y-m-d\TH:i:s.v\Z'),
            $accepted->assertion->nameId->value,
            $accepted->assertion->nameId->format->name,
            count($accepted->assertion->attributes),
        ));

        return [$browser, $accepted];
    }

    /**
     * Direction 2, logout: the model's LogoutRequest, sent by RedirectSender signed to realm idp's single logout
     * service for HTTP-Redirect; realm idp's LogoutResponse, over HTTP-POST read from the form of the page and received
     * by PostReceiver, or over HTTP-Redirect received by RedirectReceiver, then validated.
     */
    public function logoutAtKeycloak(Browser $browser, AcceptedAssertion $accepted, IdentityProvider $realmIdp, ?string $relayState): void
    {
        $request = $this->logoutRequestTo($realmIdp, $accepted);
        $url = new RedirectSender()->logoutRequest($request, $this->signing('sp'), $relayState);
        $browser->get($url)->followWithin(KEYCLOAK . '/realms/idp/');
        if (post_binding_page($browser)) {
            $form = $browser->form('form of the LogoutResponse');
            if ($form->action !== BINDINGS_SP_SLO) {
                throw new RuntimeException(sprintf('realm idp posts its LogoutResponse to %s', $form->action));
            }
            $body = $form->body();
            $this->keep('idp-logoutresponse-to-bindings-form', $body);
            $this->run->say(sprintf(
                'realm idp verified the LogoutRequest %s, signed by RedirectSender, and answers over HTTP-POST: its form posts the fields %s; SAMLResponse of %d characters, %s; RelayState %s',
                $request->id,
                implode(', ', $form->names()),
                strlen((string) $form->field('SAMLResponse')),
                $form->wrapped('SAMLResponse') ? 'WRAPPED' : 'on one line',
                relay_state_of($form->field('RelayState'), $relayState),
            ));
            $received = new PostReceiver(SamlLoader::create())->logoutMessage(BrowserForm::parsed($body));
        } else {
            [$endpoint, $query] = split_url($browser->redirect('a redirect to the single logout service of this package, or a form'));
            if ($endpoint !== BINDINGS_SP_SLO) {
                throw new RuntimeException(sprintf('realm idp answered to %s', $endpoint));
            }
            $this->keep('idp-logoutresponse-to-bindings-query', $query);
            $this->run->say(sprintf(
                'realm idp verified the LogoutRequest %s, signed by RedirectSender, and answers over HTTP-Redirect: its query string, %s; RelayState as sent %s',
                $request->id,
                query_described($query),
                query_value($query, 'RelayState') ?? 'absent',
            ));
            $received = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
        }
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new RuntimeException('realm idp answered with no LogoutResponse');
        }
        if ($received->relayState !== $relayState) {
            throw new RuntimeException(sprintf('the receiver returned the RelayState %s', var_export($received->relayState, true)));
        }
        $response = $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), $this->clock),
            $realmIdp,
            $this->serviceProvider(),
            BINDINGS_SP_SLO,
            $request->id,
        );
        if ($response->response->status->code !== StatusCode::Success) {
            throw new RuntimeException(sprintf('realm idp answered %s', $response->response->status->code->name));
        }
        $this->run->say(sprintf(
            'the receiver returned the RelayState as sent, and the model accepted the LogoutResponse %s (%s, %s), issued %s, status %s',
            $response->response->id,
            $received->binding->name,
            $response->authentication->name,
            $response->response->issueInstant->format('Y-m-d\TH:i:s.v\Z'),
            $response->response->status->code->name,
        ));
    }

    /**
     * Probes at realm idp's single sign-on service: an AuthnRequest this package signed, accepted as sent, then changed
     * after signing, each change sent in a browser of its own, which realm idp must refuse.
     */
    public function probeAuthnRequests(IdentityProvider $realmIdp): void
    {
        $sender = new RedirectSender();
        $genuine = $sender->authnRequest($this->authnRequestTo($realmIdp), $this->signing('sp'), 'bindings-probe');
        $other = $sender->authnRequest($this->authnRequestTo($realmIdp), $this->signing('sp'), 'bindings-probe');
        if (! login_page(new Browser()->get($genuine))) {
            throw new RuntimeException('realm idp did not accept the genuine AuthnRequest');
        }
        $this->run->say('realm idp accepted the genuine AuthnRequest');
        foreach (query_tampered($genuine, $other, 'SAMLRequest') as $what => $url) {
            $this->refused(new Browser()->get($url), 'realm idp, an AuthnRequest ' . $what);
        }
    }

    /**
     * Probes at realm idp's single logout service, the browser logged in: a LogoutRequest this package signed,
     * changed after signing, which realm idp must refuse, the genuine one sent afterwards.
     */
    public function probeLogoutRequests(Browser $browser, AcceptedAssertion $accepted, IdentityProvider $realmIdp): void
    {
        $sender = new RedirectSender();
        $genuine = $sender->logoutRequest($this->logoutRequestTo($realmIdp, $accepted), $this->signing('sp'), 'bindings-probe');
        $other = $sender->logoutRequest($this->logoutRequestTo($realmIdp, $accepted), $this->signing('sp'), 'bindings-probe');
        foreach (query_tampered($genuine, $other, 'SAMLRequest') as $what => $url) {
            $this->refused($browser->get($url), 'realm idp, a LogoutRequest ' . $what);
        }
    }

    /**
     * Measure: the SigAlg realm idp's single sign-on service accepts. Each AuthnRequest in a browser of its own,
     * accepted when realm idp shows its login page, refused when it answers with its error page. What the package
     * signs, RedirectSender signs; what it refuses to sign is signed by hand, for the measure only.
     */
    public function measureSignatureAlgorithms(IdentityProvider $realmIdp): void
    {
        $sender = new RedirectSender();
        foreach (SignatureAlgorithm::cases() as $algorithm) {
            if (! $algorithm->isAvailable()) {
                $this->run->say(sprintf('SigAlg %s: not measured, this build of PHP lacks it', $algorithm->value));
                continue;
            }
            $url = $sender->authnRequest(
                $this->authnRequestTo($realmIdp),
                new Signing(PrivateKey::fromPem($this->pem('sp-signing-key.pem')), $algorithm),
                'bindings-measure',
            );
            $this->outcome(new Browser()->get($url), sprintf('SigAlg %s, signed by RedirectSender', $algorithm->value));
        }
        $unsigned = $sender->authnRequest($this->authnRequestTo($realmIdp), null, 'bindings-measure');
        foreach ([
            ['http://www.w3.org/2000/09/xmldsig#rsa-sha1', OPENSSL_ALGO_SHA1, 'RSA with SHA-1'],
            ['http://www.w3.org/2001/04/xmlenc#rsa-1_5', OPENSSL_ALGO_SHA1, 'RSA with SHA-1, the URI of an encryption algorithm'],
            ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha224', OPENSSL_ALGO_SHA224, 'RSA with SHA-224'],
            ['urn:example:unknown-signature-algorithm', OPENSSL_ALGO_SHA256, 'RSA with SHA-256, under an unknown URI'],
        ] as [$uri, $digest, $how]) {
            $this->outcome(
                new Browser()->get(signed_by_hand($unsigned, $uri, $digest, $this->pem('sp-signing-key.pem'))),
                sprintf('SigAlg %s, %s, signed by hand', $uri, $how),
            );
        }
    }

    /**
     * Measure: how realm idp decodes a RelayState, a space written "%20" by RedirectSender and written "+" by hand,
     * both signed; read back from the form of its response, in one browser logged in once.
     */
    public function measureRelayStateDecoding(IdentityProvider $realmIdp): void
    {
        $browser = new Browser();
        $sender = new RedirectSender();
        $url = $sender->authnRequest($this->authnRequestTo($realmIdp), $this->signing('sp'), 'a b');
        $form = log_in($browser->get($url))->form('form of the response');
        $this->run->say(sprintf(
            'RelayState "a%%20b", as RedirectSender writes "a b": realm idp echoes %s',
            var_export($form->field('RelayState'), true),
        ));
        $unsigned = $sender->authnRequest($this->authnRequestTo($realmIdp), null, 'a b');
        $plus = signed_by_hand(
            str_replace('RelayState=a%20b', 'RelayState=a+b', $unsigned),
            SignatureAlgorithm::RsaSha256->value,
            OPENSSL_ALGO_SHA256,
            $this->pem('sp-signing-key.pem'),
        );
        $browser->get($plus)->followWithin(KEYCLOAK . '/realms/idp/');
        $this->run->say(sprintf(
            'RelayState "a+b", signed by hand: %s',
            post_binding_page($browser)
                ? 'realm idp echoes ' . var_export($browser->form('form of the response')->field('RelayState'), true)
                : sprintf('HTTP %d%s', $browser->status, $browser->error()),
        ));
    }

    /**
     * The broker's AuthnRequest: a login started at the OpenID Connect client $client of realm sp toward the identity
     * provider facing this package, followed inside realm sp to its redirect to this package's single sign-on service,
     * whose raw query string is returned, as the consumer reads it from QUERY_STRING.
     */
    private function brokerAuthnRequest(Browser $browser, string $client = 'capture'): string
    {
        $url = $browser->get(client_login(BROKER, $client))->followWithin(KEYCLOAK . '/realms/sp/')
            ->redirect('a redirect to the single sign-on service of this package');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== BINDINGS_SSO) {
            throw new RuntimeException(sprintf('the broker sent to %s', $endpoint));
        }

        return $query;
    }

    /**
     * A measure's outcome: accepted when realm idp shows its login page, refused when it answers with its error page.
     */
    private function outcome(Browser $browser, string $what): void
    {
        $this->run->say(sprintf(
            '%s: %s',
            $what,
            login_page($browser) ? 'accepted' : sprintf('refused, HTTP %d%s', $browser->status, $browser->error()),
        ));
    }

    /**
     * A probe's outcome: Keycloak must answer with its error page, never with a redirect or a form onwards.
     */
    private function refused(Browser $browser, string $what): void
    {
        if (! keycloak_refused($browser)) {
            throw new RuntimeException(sprintf('accepted by %s: HTTP %d%s', $what, $browser->status, $browser->location === null ? '' : ', to ' . $browser->location));
        }
        $this->run->say(sprintf('refused by %s, HTTP %d%s', $what, $browser->status, $browser->error()));
    }

    /**
     * Keycloak's metadata at $path, kept as served, read as the model reads metadata a channel vouches for.
     */
    private function read(string $path, string $keep): EntityDescriptor
    {
        $metadata = new Browser()->get(KEYCLOAK . $path);
        if ($metadata->status !== 200) {
            throw new RuntimeException(sprintf('GET %s: HTTP %d', $path, $metadata->status));
        }
        $this->keep($keep, $metadata->body, 'xml');

        return new MetadataReader(SamlLoader::create(), $this->clock)->readTrusted(SamlLoader::create()->load($metadata->body));
    }

    /**
     * The metadata of a role of this package, written and signed by the model with the key of that role, kept in
     * written/ as given to Keycloak.
     *
     * @param 'idp'|'sp' $role
     */
    private function metadata(string $name, EntityDescriptor $descriptor, string $role): string
    {
        $bytes = new Serializer()->serialize(new MetadataWriter()->write($descriptor, $this->signing($role)));
        file_put_contents(sprintf('%s/%s.xml', $this->written, $name), $bytes);

        return $bytes;
    }

    /**
     * This package's answer to the broker's accepted AuthnRequest: the persistent subject SUBJECT, a bearer window and
     * conditions of 300 s from now, which the broker checks with no skew (allowedClockSkew 0), two attributes whose
     * values carry no xsi:type, as saml2-model's harness answered.
     */
    private function responseTo(AcceptedAuthnRequest $accepted, ServiceProvider $broker): Response
    {
        $now = $this->clock->second();
        $acs = $accepted->assertionConsumerService->location;

        return new Response(
            SamlId::generate(),
            $now,
            new Issuer(BINDINGS_IDP),
            $acs,
            $accepted->request->id,
            new Status(StatusCode::Success),
            new Assertion(
                SamlId::generate(),
                $now,
                new Issuer(BINDINGS_IDP),
                new NameId(SUBJECT, NameIdFormat::Persistent),
                new SubjectConfirmation($acs, $now->modify('+300 seconds'), $accepted->request->id, null),
                new Conditions($now, $now->modify('+300 seconds'), [[$broker->entityId]], false),
                new AuthnStatement($now, SamlId::generate(), null, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'),
                [
                    new Attribute('email', AttributeNameFormat::Basic, null, ['alice@saml2-bindings.test']),
                    new Attribute('Role', AttributeNameFormat::Basic, null, ['member', 'reader']),
                ],
            ),
        );
    }

    /**
     * This package's answer to the broker's accepted LogoutRequest, to its single logout service for HTTP-Redirect.
     */
    private function logoutResponseTo(LogoutRequest $request, ServiceProvider $broker): LogoutResponse
    {
        $endpoint = self::redirectEndpoint($broker->singleLogoutServices, 'the single logout service of the broker');

        return new LogoutResponse(
            SamlId::generate(),
            $this->clock->second(),
            new Issuer(BINDINGS_IDP),
            $endpoint->responseLocation ?? $endpoint->location,
            $request->id,
            new Status(StatusCode::Success),
        );
    }

    /**
     * The model's AuthnRequest to realm idp's single sign-on service for HTTP-Redirect, a persistent identifier asked,
     * as the broker asks, and the response over HTTP-POST.
     */
    private function authnRequestTo(IdentityProvider $realmIdp): AuthnRequest
    {
        return new AuthnRequest(
            SamlId::generate(),
            $this->clock->second(),
            new Issuer(BINDINGS_SP),
            self::redirectEndpoint($realmIdp->singleSignOnServices, 'the single sign-on service of realm idp')->location,
            BINDINGS_ACS,
            null,
            Binding::HttpPost->value,
            new NameIdPolicy(NameIdFormat::Persistent->value, null, true),
        );
    }

    /**
     * The model's LogoutRequest for the session an accepted response opened, to realm idp's single logout service for
     * HTTP-Redirect.
     */
    private function logoutRequestTo(IdentityProvider $realmIdp, AcceptedAssertion $accepted): LogoutRequest
    {
        $sessionIndex = $accepted->assertion->authnStatement->sessionIndex;

        return new LogoutRequest(
            SamlId::generate(),
            $this->clock->second(),
            new Issuer(BINDINGS_SP),
            self::redirectEndpoint($realmIdp->singleLogoutServices, 'the single logout service of realm idp')->location,
            null,
            $accepted->assertion->nameId,
            $sessionIndex === null ? [] : [$sessionIndex],
        );
    }

    /**
     * PostSender's form, submitted by the browser to its action, its fields encoded as a browser encodes them.
     */
    private function submit(Browser $browser, PostForm $form): Browser
    {
        $fields = [];
        foreach ($form->fields as $name => $value) {
            $fields[] = [$name, $value];
        }

        return $browser->post($form->action, BrowserForm::body($fields));
    }

    /**
     * The endpoint of $endpoints for HTTP-Redirect, the binding this package's judge plays.
     *
     * @param list<Endpoint> $endpoints
     */
    private static function redirectEndpoint(array $endpoints, string $what): Endpoint
    {
        foreach ($endpoints as $endpoint) {
            if ($endpoint->binding === Binding::HttpRedirect) {
                return $endpoint;
            }
        }

        throw new RuntimeException(sprintf('%s is not published for HTTP-Redirect', $what));
    }

    /**
     * The bindings of $endpoints, in their order.
     *
     * @param list<Endpoint> $endpoints
     */
    private static function bindings(array $endpoints): string
    {
        return implode(', ', array_map(static fn (Endpoint $endpoint): string => $endpoint->binding->name, $endpoints));
    }

    /**
     * @param 'idp'|'sp' $role
     */
    private function signing(string $role): Signing
    {
        return new Signing(PrivateKey::fromPem($this->pem(sprintf('%s-signing-key.pem', $role))));
    }

    /**
     * @param 'idp'|'sp' $role
     */
    private function certificate(string $role): string
    {
        return (string) preg_replace('~-----[A-Z ]+-----|\s+~', '', $this->pem(sprintf('%s-signing-certificate.pem', $role)));
    }

    private function pem(string $file): string
    {
        return (string) file_get_contents($this->keys . '/' . $file);
    }

    /**
     * A capture, kept once in the run.
     */
    private function keep(string $what, string $bytes, string $extension = 'txt'): void
    {
        if (isset($this->kept[$what])) {
            return;
        }
        $this->kept[$what] = true;
        $this->run->keep($what, $bytes, $extension);
    }
}

$run = keycloak_run($argv);
if (! is_dir(__DIR__ . '/written')) {
    mkdir(__DIR__ . '/written');
}
wait_for_keycloak();
$exchange = new Exchange($run, __DIR__ . '/written', __DIR__ . '/../../Fixture/keys');
$admin = new Admin();
// RelayStates chosen to measure what realm idp echoes: a space and a "~", whose escaping differs between RFC 3986 and
// urlencode(), and 80 bytes, the bound of SAML Bindings §3.4.3.
$eighty = str_pad('bindings ~ 80 bytes ', 80, '0123456789');

$realmIdp = $run->step(
    'Keycloak configured from this package\'s metadata by its own importers',
    static fn (): IdentityProvider => $exchange->configure($admin),
);
if (! $realmIdp instanceof IdentityProvider) {
    $run->exit();
}

$run->step(
    'this package as identity provider, the broker as import-config set it, HTTP-Redirect throughout: its AuthnRequest',
    static fn () => $exchange->brokerAsImported(),
);
$broker = $run->step(
    'the broker\'s "HTTP-POST binding response" switched on in the console, its requests left on HTTP-Redirect',
    static function () use ($exchange, $admin): ServiceProvider {
        $exchange->brokerSetting($admin, 'postBindingResponse', 'true');

        return $exchange->broker('sp-metadata-for-bindings');
    },
);
$login = $broker instanceof ServiceProvider ? $run->step(
    'this package as identity provider, the broker in front: login',
    static fn (): array => $exchange->loginAtThePackage($broker),
) : null;
if (is_array($login) && $broker instanceof ServiceProvider) {
    $run->step(
        'this package as identity provider: logout, with the probes of a LogoutResponse changed after signing',
        static fn () => $exchange->logoutAtThePackage($login[0], $login[1], $login[2], $broker),
    );
}
$run->step(
    'measure: the broker\'s RelayState for a client whose internal ID is not a UUID',
    static fn () => $exchange->measureBrokerRelayState($admin, 'a-client-of-realm-sp-whose-internal-id-is-no-uuid'),
);

$login = $run->step(
    'this package as service provider, realm idp in front, its client under the server\'s defaults: login',
    static fn (): array => $exchange->loginAtKeycloak($realmIdp, 'bindings login ~'),
);
if (is_array($login)) {
    $run->step(
        'probes: realm idp and a LogoutRequest of this package changed after signing',
        static fn () => $exchange->probeLogoutRequests($login[0], $login[1], $realmIdp),
    );
    $run->step(
        'this package as service provider: logout, saml.force.post.binding on, the server\'s default',
        static fn () => $exchange->logoutAtKeycloak($login[0], $login[1], $realmIdp, 'bindings logout ~'),
    );
}
$run->step(
    'realm idp\'s "Force POST binding" switched off in the console',
    static fn () => $exchange->clientSetting($admin, 'saml.force.post.binding', 'false'),
);
$login = $run->step(
    'this package as service provider, saml.force.post.binding off: login',
    static fn (): array => $exchange->loginAtKeycloak($realmIdp, null),
);
if (is_array($login)) {
    $run->step(
        'this package as service provider, saml.force.post.binding off: logout',
        static fn () => $exchange->logoutAtKeycloak($login[0], $login[1], $realmIdp, $eighty),
    );
}
$run->step(
    'probes: realm idp and an AuthnRequest of this package changed after signing',
    static fn () => $exchange->probeAuthnRequests($realmIdp),
);
$run->step(
    'measure: the SigAlg realm idp\'s single sign-on service accepts',
    static fn () => $exchange->measureSignatureAlgorithms($realmIdp),
);
$run->step(
    'measure: how realm idp decodes a space in a RelayState',
    static fn () => $exchange->measureRelayStateDecoding($realmIdp),
);

$run->exit();
