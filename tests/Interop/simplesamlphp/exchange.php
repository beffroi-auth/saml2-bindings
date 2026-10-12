<?php

declare(strict_types=1);

/*
 * The exchange (README.md of this directory, section 4): this package and the SimpleSAMLphp installation of
 * installation/, both ways, as a service provider and as an identity provider, login and logout, then the probes and
 * the measures of section 9.5 of spec/bindings.md, on the running installation, with the package of the repository
 * (its vendor/autoload.php), the test keys of tests/Fixture/keys/ and the live clock.
 *
 * The script is the browser and the HTTP layer of this package's roles, which answer at http://localhost:8093/bindings/
 * where nothing listens: it intercepts every message addressed there. It is saml2-model's exchange.php, at its commit
 * 9c833c5, with every line that played the binding replaced by this package: RedirectSender writes every URL this
 * package sends, PostSender every form, RedirectReceiver reads every query string SimpleSAMLphp sends and PostReceiver
 * every form, read from the page by the harness (../harness.php) and encoded as a browser does. No gzinflate(), no
 * base64_decode(), no http_build_query() and no octets built by hand, except where a measure needs what the package
 * refuses to write (an RSA-SHA1 signature, a SigAlg off its list, a "+" in a signed RelayState): those are built in
 * signed_by_hand() of ../harness.php, named so, and sent for the measure only.
 *
 * This package's metadata, both roles, written by the model's MetadataWriter, go to written/, from which the
 * installation reads them; what SimpleSAMLphp sent goes to received/, or to tests/Fixture/real/ with --keep, named
 * with its version and the date. One line per step and per measure; the exit status is 1 when a step fails.
 *
 * From the root of the repository, the installation up (castor simplesamlphp runs it all):
 *   docker run --rm --network saml2-bindings-simplesamlphp_default \
 *       -e EXCHANGE_CONNECT_TO=localhost:8091:idp:80,localhost:8092:sp:80 -v "$PWD:/project" -w /project \
 *       ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/exchange.php [--keep]
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
use Beffroi\Saml2\Model\Exception\SignatureRequired;
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
use Psr\Clock\ClockInterface;

require __DIR__ . '/harness.php';

const FOR_BINDINGS = SP . '/module.php/saml/sp/metadata/for-bindings';
const SESSION = SP . '/session.php';

/**
 * A service provider of this package facing SimpleSAMLphp's identity provider, and how that identity provider answers
 * its logout, which saml20-sp-remote.php of the installation sets per entity; the RelayState each sends, chosen to
 * measure what the identity provider echoes (section 9.5 point 4).
 */
final readonly class Variant
{
    public function __construct(
        public string $name,
        public string $what,
        public Binding $logoutBinding,
        public bool $logoutSigned,
        public ?string $loginRelayState,
        public ?string $logoutRelayState,
    ) {
    }

    public function entityId(): string
    {
        return BINDINGS . '/' . $this->name;
    }

    public function acs(): string
    {
        return $this->entityId() . '/acs';
    }

    public function slo(): string
    {
        return $this->entityId() . '/slo';
    }
}

final class Exchange
{
    /**
     * What this package's identity provider asserts: the attributes the service provider's session must then hold.
     *
     * @var array<string, list<string>>
     */
    private const array ATTRIBUTES = ['uid' => ['bindings-student'], 'eduPersonAffiliation' => ['member', 'student']];

    private readonly ClockInterface $clock;

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
     * This package's identity provider: HTTP-Redirect for its single sign-on and single logout services, wanting its
     * requests signed.
     */
    public function identityProvider(): IdentityProvider
    {
        return new IdentityProvider(
            BINDINGS . '/idp',
            [$this->certificate('idp')],
            [],
            [new Endpoint(Binding::HttpRedirect, BINDINGS . '/idp/sso')],
            [new Endpoint(Binding::HttpRedirect, BINDINGS . '/idp/slo')],
            [NameIdFormat::Transient],
            wantAuthnRequestsSigned: true,
        );
    }

    /**
     * A service provider of this package: its assertion consumer service over HTTP-POST, its single logout service
     * over the binding of its variant, signing its requests and wanting its assertions signed.
     */
    public function serviceProvider(Variant $variant): ServiceProvider
    {
        return new ServiceProvider(
            $variant->entityId(),
            [$this->certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, $variant->acs(), 0, true)]),
            [new Endpoint($variant->logoutBinding, $variant->slo())],
            [NameIdFormat::Transient],
            authnRequestsSigned: true,
            wantAssertionsSigned: true,
        );
    }

    /**
     * The metadata of this package's roles, written and signed by the model with the key of each, where the
     * installation reads them (SimpleSAMLphp parses its metadata at every request).
     *
     * @param list<Variant> $variants
     */
    public function writeMetadata(array $variants): void
    {
        foreach (glob($this->written . '/*.xml') ?: [] as $file) {
            unlink($file);
        }
        $writer = new MetadataWriter();
        $documents = [
            'bindings-idp-metadata' => $writer->write(
                new EntityDescriptor(BINDINGS . '/idp', identityProvider: $this->identityProvider()),
                $this->signing('idp'),
            ),
        ];
        foreach ($variants as $variant) {
            $documents[sprintf('bindings-%s-metadata', $variant->name)] = $writer->write(
                new EntityDescriptor($variant->entityId(), serviceProvider: $this->serviceProvider($variant)),
                $this->signing('sp'),
            );
        }
        foreach ($documents as $name => $document) {
            file_put_contents(sprintf('%s/%s.xml', $this->written, $name), new Serializer()->serialize($document));
        }
        $this->run->say(sprintf('wrote the metadata of %d roles of this package into written/', count($documents)));
    }

    /**
     * The identity provider's metadata, read live, kept once; its single sign-on service must be published as
     * SimpleSAMLphp does by default, HTTP-Redirect alone.
     */
    public function identityProviderLive(): IdentityProvider
    {
        $metadata = new Browser()->get(IDP . '/module.php/saml/idp/metadata');
        if ($metadata->status !== 200) {
            throw new RuntimeException(sprintf('the metadata of the identity provider: HTTP %d', $metadata->status));
        }
        $this->keep('idp-metadata', $metadata->body, 'xml');
        $idp = $this->reader()->readTrusted(SamlLoader::create()->load($metadata->body))->identityProvider
            ?? throw new RuntimeException('the metadata of the identity provider holds no identity provider');
        $bindings = array_map(static fn (Endpoint $endpoint): string => $endpoint->binding->name, $idp->singleSignOnServices);
        if ($bindings !== ['HttpRedirect']) {
            throw new RuntimeException(sprintf('the single sign-on service is published for %s', implode(', ', $bindings)));
        }
        $this->run->say('the identity provider publishes its single sign-on service for HTTP-Redirect alone, its default');

        return $idp;
    }

    /**
     * Direction 1, login: this package as a service provider, SimpleSAMLphp's identity provider in front. The model's
     * AuthnRequest, sent by RedirectSender signed to the single sign-on service; the test user's login; the response
     * read from the form of the page, posted as a browser posts it, received by PostReceiver and validated by the
     * model. Returns the browser, logged in at the identity provider, and what the model accepted.
     *
     * @return array{Browser, AcceptedAssertion, AuthnRequest}
     */
    public function loginAtTheIdentityProvider(Variant $variant, IdentityProvider $idp, bool $keep): array
    {
        $browser = new Browser();
        $request = $this->authnRequestTo($idp, $variant);
        $url = new RedirectSender()->authnRequest($request, $this->signing('sp'), $variant->loginRelayState);
        $login = $browser->get($url)->redirect('a redirect to the login page, the AuthnRequest accepted');
        if (! str_starts_with($login, IDP . '/module.php/core/loginuserpass')) {
            throw new RuntimeException(sprintf('the single sign-on service sent to %s', $login));
        }
        $this->run->say(sprintf(
            'the identity provider verified the AuthnRequest %s of %s, its query string of %d bytes signed by RedirectSender, and took it to its login page',
            $request->id,
            $variant->name,
            strlen(split_url($url)[1]),
        ));

        $form = log_in($browser->followWithin(IDP . '/'))->form('form of the response');
        $value = (string) $form->field('SAMLResponse');
        $this->run->say(sprintf(
            'its form posts to %s the fields %s; SAMLResponse of %d characters, %s; RelayState %s',
            $form->action,
            implode(', ', $form->names()),
            strlen($value),
            preg_match('/[\r\n]/', $value) === 1 ? 'WRAPPED' : 'on one line',
            relay_state_of($form->field('RelayState'), $variant->loginRelayState),
        ));
        if ($form->action !== $variant->acs()) {
            throw new RuntimeException(sprintf('the identity provider posts its response to %s', $form->action));
        }
        $body = $form->body();
        if ($keep) {
            $this->keep('idp-response-to-bindings-form', $body);
        }
        $received = new PostReceiver(SamlLoader::create())->response(BrowserForm::parsed($body));
        if ($received->relayState !== $variant->loginRelayState) {
            throw new RuntimeException('PostReceiver returned another RelayState than the one sent');
        }
        $accepted = $received->validate(
            new ResponseValidator(SamlLoader::create(), $this->clock, new InMemoryReplayGuard()),
            $idp,
            ExpectedResponse::toRequest($request->id, $variant->acs(), $variant->entityId()),
        );
        $this->run->say(sprintf(
            'PostReceiver read and the model accepted the response %s (%s), issued %s, NameID %s, attributes %s',
            $accepted->responseId,
            $accepted->coverage->name,
            $accepted->assertion->issueInstant->format('Y-m-d\TH:i:s\Z'),
            $accepted->assertion->nameId->value,
            json_encode(
                array_map(
                    static fn (Attribute $attribute): array => [$attribute->name => $attribute->values],
                    $accepted->assertion->attributes,
                ),
                JSON_UNESCAPED_SLASHES,
            ),
        ));

        return [$browser, $accepted, $request];
    }

    /**
     * Direction 1, logout: the model's LogoutRequest, sent by RedirectSender signed to the single logout service; the
     * identity provider's LogoutResponse, over HTTP-Redirect received by RedirectReceiver, or over HTTP-POST read from
     * the form of the page and received by PostReceiver, then validated: accepted signed, refused unsigned.
     */
    public function logoutAtTheIdentityProvider(Variant $variant, Browser $browser, AcceptedAssertion $accepted, IdentityProvider $idp): void
    {
        $request = $this->logoutRequestTo($idp, $variant, $accepted);
        $url = new RedirectSender()->logoutRequest($request, $this->signing('sp'), $variant->logoutRelayState);
        $browser->get($url)->followWithin(IDP . '/');
        $this->run->say(sprintf('the identity provider verified the LogoutRequest %s of %s, signed by RedirectSender', $request->id, $variant->name));

        if ($variant->logoutBinding === Binding::HttpPost) {
            $form = $browser->form('form of the LogoutResponse');
            if ($form->action !== $variant->slo()) {
                throw new RuntimeException(sprintf('the identity provider posts its LogoutResponse to %s', $form->action));
            }
            $body = $form->body();
            $this->keep('idp-logoutresponse-to-bindings-form', $body);
            $received = new PostReceiver(SamlLoader::create())->logoutMessage(BrowserForm::parsed($body));
            $value = (string) $form->field('SAMLResponse');
            $this->run->say(sprintf(
                'its form posts the fields %s; SAMLResponse of %d characters, %s; RelayState %s',
                implode(', ', $form->names()),
                strlen($value),
                preg_match('/[\r\n]/', $value) === 1 ? 'WRAPPED' : 'on one line',
                relay_state_of($form->field('RelayState'), $variant->logoutRelayState),
            ));
        } else {
            [$endpoint, $query] = split_url($browser->redirect('a redirect to the single logout service of ' . $variant->name));
            if ($endpoint !== $variant->slo()) {
                throw new RuntimeException(sprintf('the identity provider answered to %s', $endpoint));
            }
            $this->keep(
                $variant->logoutSigned ? 'idp-logoutresponse-to-bindings-query' : 'idp-logoutresponse-to-bindings-unsigned-refused-query',
                $query,
            );
            $this->run->say(sprintf('its query string, %s; RelayState as sent %s', query_described($query), query_value($query, 'RelayState') ?? 'absent'));
            $received = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
        }
        if (! $received instanceof ReceivedLogoutResponse) {
            throw new RuntimeException('the identity provider answered with no LogoutResponse');
        }
        if ($received->relayState !== $variant->logoutRelayState) {
            throw new RuntimeException(sprintf('the receiver returned the RelayState %s', var_export($received->relayState, true)));
        }
        $validator = new LogoutResponseValidator(SamlLoader::create(), $this->clock);
        $self = $this->serviceProvider($variant);
        if (! $variant->logoutSigned) {
            try {
                $received->validate($validator, $idp, $self, $variant->slo(), $request->id);
            } catch (SignatureRequired $refused) {
                $this->run->say(sprintf(
                    'the receiver returned the RelayState as sent; its LogoutResponse unsigned, validate() refused it: %s',
                    $refused->getMessage(),
                ));

                return;
            }
            throw new RuntimeException('the model accepted an unsigned LogoutResponse');
        }
        $response = $received->validate($validator, $idp, $self, $variant->slo(), $request->id);
        if ($response->response->status->code !== StatusCode::Success) {
            throw new RuntimeException(sprintf('the identity provider answered %s', $response->response->status->code->name));
        }
        $this->run->say(sprintf(
            'the receiver returned the RelayState as sent, and the model accepted the LogoutResponse %s (%s), issued %s, in response to %s, status %s',
            $response->response->id,
            $response->authentication->name,
            $response->response->issueInstant->format('Y-m-d\TH:i:s\Z'),
            $request->id,
            $response->response->status->code->name,
        ));
    }

    /**
     * Probes at the single sign-on service: an AuthnRequest this package signed, accepted as sent, then changed after
     * signing, each change sent in a browser of its own, which the identity provider must refuse.
     */
    public function probeAuthnRequests(IdentityProvider $idp, Variant $variant): void
    {
        $sender = new RedirectSender();
        $genuine = $sender->authnRequest($this->authnRequestTo($idp, $variant), $this->signing('sp'), 'bindings-probe');
        $other = $sender->authnRequest($this->authnRequestTo($idp, $variant), null, 'bindings-probe');
        $this->accepted(new Browser()->get($genuine), IDP . '/module.php/core/loginuserpass', 'the genuine AuthnRequest');
        foreach (query_tampered($genuine, $other, 'SAMLRequest') as $what => $url) {
            $this->refused(new Browser()->get($url), 'an AuthnRequest ' . $what);
        }
    }

    /**
     * Probes at the single logout service, the browser logged in: a LogoutRequest this package signed, changed after
     * signing, which the identity provider must refuse, the session staying open for the genuine one.
     */
    public function probeLogoutRequests(Browser $browser, AcceptedAssertion $accepted, IdentityProvider $idp, Variant $variant): void
    {
        $sender = new RedirectSender();
        $genuine = $sender->logoutRequest($this->logoutRequestTo($idp, $variant, $accepted), $this->signing('sp'), 'bindings-probe');
        $other = $sender->logoutRequest($this->logoutRequestTo($idp, $variant, $accepted), $this->signing('sp'), 'bindings-probe');
        foreach (query_tampered($genuine, $other, 'SAMLRequest') as $what => $url) {
            $this->refused($browser->get($url), 'a LogoutRequest ' . $what);
        }
    }

    /**
     * Direction 2, login: this package as an identity provider, SimpleSAMLphp's service provider for-bindings in
     * front. Its AuthnRequest, over HTTP-Redirect signed, received by RedirectReceiver and validated by the model; the
     * model's response, posted through PostSender's form to its assertion consumer service, opens its session with
     * the attributes this package sent. Returns the browser, logged in, and what this package asserted.
     *
     * @return array{Browser, Assertion, ServiceProvider}
     */
    public function loginAtThePackage(SignedParts $parts, bool $keep): array
    {
        $browser = new Browser();
        $sp = $this->forBindings($browser);
        $url = $browser->get(SP . '/module.php/saml/sp/login/for-bindings?ReturnTo=' . rawurlencode(SESSION))
            ->redirect('a redirect to the single sign-on service of this package');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== BINDINGS . '/idp/sso') {
            throw new RuntimeException(sprintf('for-bindings sent to %s', $endpoint));
        }
        if ($keep) {
            $this->keep('sp-authnrequest-to-bindings-query', $query);
        }
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
        $accepted = $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), $this->clock),
            $sp,
            $this->identityProvider(),
            BINDINGS . '/idp/sso',
        );
        $this->run->say(sprintf(
            'RedirectReceiver verified and the model accepted the AuthnRequest %s of for-bindings (%s), issued %s; its query string, %s; RelayState of %d bytes; its assertion consumer service %s',
            $accepted->request->id,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
            query_described($query),
            strlen((string) $received->relayState),
            $accepted->assertionConsumerService->location,
        ));

        $response = $this->responseTo($accepted, $sp);
        $assertion = $response->assertion ?? throw new LogicException('the response carries its assertion');
        $form = new PostSender()->response($response, $this->signing('idp'), $parts, $received->relayState);
        $returned = $this->submit($browser, $form)->redirect('a redirect from the assertion consumer service, the response accepted');
        if ($returned !== SESSION) {
            throw new RuntimeException(sprintf('the assertion consumer service sent to %s', $returned));
        }
        $session = $this->session($browser);
        $expected = [
            'authenticated' => true,
            'idp' => BINDINGS . '/idp',
            'nameId' => [
                'value' => $assertion->nameId->value,
                'format' => NameIdFormat::Transient->value,
                'spNameQualifier' => $sp->entityId,
            ],
            'sessionIndex' => $assertion->authnStatement->sessionIndex,
            'attributes' => self::ATTRIBUTES,
        ];
        if ($session !== $expected) {
            throw new RuntimeException(sprintf('the session of for-bindings holds %s', json_encode($session)));
        }
        $this->run->say(sprintf(
            'for-bindings accepted the response %s (%s), posted through PostSender\'s form with the RelayState it sent, and opened its session: %s',
            $response->id,
            $parts->name,
            json_encode($session['attributes'], JSON_UNESCAPED_SLASHES),
        ));

        return [$browser, $assertion, $sp];
    }

    /**
     * Direction 2, logout: for-bindings's LogoutRequest, over HTTP-Redirect signed, received by RedirectReceiver and
     * validated by the model; this package's LogoutResponse, sent by RedirectSender signed to its single logout
     * service, closes its session. With probes, the LogoutResponse is first sent changed after signing, which for-bindings
     * must refuse.
     */
    public function logoutAtThePackage(Browser $browser, Assertion $assertion, ServiceProvider $sp, bool $keep, bool $probes): void
    {
        $url = $browser->get(SP . '/module.php/core/logout/for-bindings?ReturnTo=' . rawurlencode(SESSION))
            ->redirect('a redirect to the single logout service of this package');
        [$endpoint, $query] = split_url($url);
        if ($endpoint !== BINDINGS . '/idp/slo') {
            throw new RuntimeException(sprintf('for-bindings sent to %s', $endpoint));
        }
        if ($keep) {
            $this->keep('sp-logoutrequest-to-bindings-query', $query);
        }
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage($query);
        if (! $received instanceof ReceivedLogoutRequest) {
            throw new RuntimeException('for-bindings sent no LogoutRequest');
        }
        $accepted = $received->validate(
            new LogoutRequestValidator(SamlLoader::create(), $this->clock),
            $sp,
            $this->identityProvider(),
            BINDINGS . '/idp/slo',
        );
        $this->run->say(sprintf(
            'RedirectReceiver verified and the model accepted the LogoutRequest %s of for-bindings (%s), issued %s; its query string, %s; RelayState of %d bytes',
            $accepted->request->id,
            $accepted->authentication->name,
            $accepted->request->issueInstant->format('Y-m-d\TH:i:s\Z'),
            query_described($query),
            strlen((string) $received->relayState),
        ));
        // What beffroi/saml does with it (section 6.8): the session it names is the one this package opened.
        if (
            $accepted->request->nameId->value !== $assertion->nameId->value
            || $accepted->request->sessionIndexes !== [$assertion->authnStatement->sessionIndex]
        ) {
            throw new RuntimeException('the LogoutRequest names another session than the one this package opened');
        }

        $sender = new RedirectSender();
        $answer = $sender->logoutResponse($this->logoutResponseTo($accepted->request, $sp), $this->signing('idp'), $received->relayState);
        if ($probes) {
            $other = $sender->logoutResponse($this->logoutResponseTo($accepted->request, $sp), $this->signing('idp'), $received->relayState);
            foreach (query_tampered($answer, $other, 'SAMLResponse') as $what => $tampered) {
                $this->refused($browser->get($tampered), 'a LogoutResponse ' . $what);
            }
        }
        $returned = $browser->get($answer)->redirect('a redirect from the single logout service, the LogoutResponse accepted');
        if ($returned !== SESSION) {
            throw new RuntimeException(sprintf('the single logout service sent to %s', $returned));
        }
        if ($this->session($browser) !== ['authenticated' => false]) {
            throw new RuntimeException('the session of for-bindings is still open');
        }
        $this->run->say('for-bindings accepted the LogoutResponse of this package, signed by RedirectSender over HTTP-Redirect, and closed its session');
    }

    /**
     * Measure: the SigAlg the single sign-on service accepts. Each AuthnRequest in a browser of its own, accepted when
     * the identity provider takes it to its login page, refused when it answers with its error page. What the package
     * signs, RedirectSender signs; what it refuses to sign is signed by hand, for the measure only.
     */
    public function measureSignatureAlgorithms(IdentityProvider $idp, Variant $variant): void
    {
        $sender = new RedirectSender();
        foreach ([SignatureAlgorithm::RsaSha256, SignatureAlgorithm::RsaSha384, SignatureAlgorithm::RsaSha512, SignatureAlgorithm::RsaPssSha256] as $algorithm) {
            if (! $algorithm->isAvailable()) {
                $this->run->say(sprintf('SigAlg %s: not measured, this build of PHP lacks it', $algorithm->value));
                continue;
            }
            $url = $sender->authnRequest(
                $this->authnRequestTo($idp, $variant),
                new Signing(PrivateKey::fromPem($this->pem('sp-signing-key.pem')), $algorithm),
                'bindings-measure',
            );
            $this->outcome(new Browser()->get($url), sprintf('SigAlg %s, signed by RedirectSender', $algorithm->value));
        }
        $unsigned = $sender->authnRequest($this->authnRequestTo($idp, $variant), null, 'bindings-measure');
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
     * Measure: how the identity provider decodes a RelayState, a space written "%20" by RedirectSender and written "+"
     * by hand, both signed; read back from the form of its response, in one browser logged in once.
     */
    public function measureRelayStateDecoding(IdentityProvider $idp, Variant $variant): void
    {
        $browser = new Browser();
        $sender = new RedirectSender();
        $url = $sender->authnRequest($this->authnRequestTo($idp, $variant), $this->signing('sp'), 'a b');
        $form = log_in($browser->get($url)->followWithin(IDP . '/'))->form('form of the response');
        $this->run->say(sprintf(
            'RelayState "a%%20b", as RedirectSender writes "a b": the identity provider echoes %s',
            var_export($form->field('RelayState'), true),
        ));
        $unsigned = $sender->authnRequest($this->authnRequestTo($idp, $variant), null, 'a b');
        $plus = signed_by_hand(
            str_replace('RelayState=a%20b', 'RelayState=a+b', $unsigned),
            SignatureAlgorithm::RsaSha256->value,
            OPENSSL_ALGO_SHA256,
            $this->pem('sp-signing-key.pem'),
        );
        $browser->get($plus)->followWithin(IDP . '/');
        $form = $browser->status === 200 ? Form::of($browser->body, $browser->url) : null;
        $this->run->say(sprintf(
            'RelayState "a+b", signed by hand: %s',
            $form === null ? sprintf('HTTP %d%s', $browser->status, $browser->error()) : 'the identity provider echoes ' . var_export($form->field('RelayState'), true),
        ));
    }

    /**
     * Measure: the RelayState of for-bindings's AuthnRequest, its ReturnTo, for a ReturnTo longer than the 80 bytes of
     * SAML Bindings §3.4.3, which B-9 reads up to 1 024 bytes (finding F-5), and for an empty and an absent one; what
     * RedirectReceiver does of each, the query string of a RelayState over 80 bytes kept.
     */
    public function measureServiceProviderRelayState(): void
    {
        $long = SESSION . '?' . str_repeat('return-to-', 6);
        foreach ([
            [sprintf('a ReturnTo of %d bytes', strlen($long)), '?ReturnTo=' . rawurlencode($long), $long],
            ['an empty ReturnTo', '?ReturnTo=', ''],
            ['no ReturnTo', '', null],
        ] as [$what, $parameters, $returnTo]) {
            $browser = new Browser()->get(SP . '/module.php/saml/sp/login/for-bindings' . $parameters);
            if (! in_array($browser->status, [302, 303], true)) {
                $this->run->say(sprintf('for-bindings, %s: no AuthnRequest, HTTP %d%s', $what, $browser->status, $browser->error()));
                continue;
            }
            [, $query] = split_url((string) $browser->location);
            $raw = query_value($query, 'RelayState');
            try {
                $received = new RedirectReceiver(SamlLoader::create())->authnRequest($query);
                $outcome = sprintf('RedirectReceiver read it, RelayState %s', $received->relayState === null ? 'absent' : strlen($received->relayState) . ' bytes');
                if (strlen((string) $received->relayState) > 80) {
                    $this->keep('sp-authnrequest-to-bindings-long-relaystate-query', $query);
                }
            } catch (Throwable $refused) {
                $outcome = sprintf('RedirectReceiver refused it: %s: %s', $refused::class, $refused->getMessage());
            }
            $this->run->say(sprintf(
                'for-bindings, %s: RelayState %s; %s',
                $what,
                $raw === null ? 'absent' : sprintf('of %d characters as sent%s', strlen($raw), $raw === urlencode((string) $returnTo) ? ', the ReturnTo urlencode()d' : ''),
                $outcome,
            ));
        }
    }

    /**
     * A measure's outcome: accepted when the identity provider takes the request to its login page, refused otherwise.
     */
    private function outcome(Browser $browser, string $what): void
    {
        $accepted = in_array($browser->status, [302, 303], true)
            && str_starts_with((string) $browser->location, IDP . '/module.php/core/loginuserpass');
        $this->run->say(sprintf('%s: %s', $what, $accepted ? 'accepted' : sprintf('refused, HTTP %d%s', $browser->status, $browser->error())));
    }

    /**
     * The control of a probe: SimpleSAMLphp must accept the genuine request, a redirect under $prefix.
     */
    private function accepted(Browser $browser, string $prefix, string $what): void
    {
        if (! in_array($browser->status, [302, 303], true) || ! str_starts_with((string) $browser->location, $prefix)) {
            throw new RuntimeException(sprintf('SimpleSAMLphp did not accept %s: HTTP %d%s', $what, $browser->status, $browser->error()));
        }
        $this->run->say(sprintf('SimpleSAMLphp accepted %s', $what));
    }

    /**
     * A probe's outcome: SimpleSAMLphp must answer with its error page, never with a redirect onwards.
     */
    private function refused(Browser $browser, string $what): void
    {
        if ($browser->status < 400) {
            throw new RuntimeException(sprintf('SimpleSAMLphp accepted %s: HTTP %d, to %s', $what, $browser->status, (string) $browser->location));
        }
        $this->run->say(sprintf('SimpleSAMLphp refused %s, HTTP %d%s', $what, $browser->status, $browser->error()));
    }

    /**
     * The metadata of for-bindings, read live, kept once.
     */
    private function forBindings(Browser $browser): ServiceProvider
    {
        $metadata = $browser->get(FOR_BINDINGS);
        if ($metadata->status !== 200) {
            throw new RuntimeException(sprintf('the metadata of for-bindings: HTTP %d', $metadata->status));
        }
        $this->keep('sp-metadata-for-bindings', $metadata->body, 'xml');

        return $this->reader()->readTrusted(SamlLoader::create()->load($metadata->body))->serviceProvider
            ?? throw new RuntimeException('the metadata of for-bindings holds no service provider');
    }

    /**
     * This package's answer to an accepted AuthnRequest: SimpleSAMLphp's windows (NotBefore 30 s back, 300 s ahead, a
     * session of 8 h), a transient NameID, the attributes of ATTRIBUTES.
     */
    private function responseTo(AcceptedAuthnRequest $accepted, ServiceProvider $sp): Response
    {
        $now = $this->second();
        $acs = $accepted->assertionConsumerService->location;
        $assertion = new Assertion(
            SamlId::generate(),
            $now,
            new Issuer(BINDINGS . '/idp'),
            new NameId(SamlId::generate(), NameIdFormat::Transient, null, $sp->entityId),
            new SubjectConfirmation($acs, $now->modify('+300 seconds'), $accepted->request->id, null),
            new Conditions($now->modify('-30 seconds'), $now->modify('+300 seconds'), [[$sp->entityId]], false),
            new AuthnStatement(
                $now,
                SamlId::generate(),
                $now->modify('+8 hours'),
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ),
            array_map(
                static fn (string $name, array $values): Attribute => new Attribute($name, AttributeNameFormat::Basic, null, $values),
                array_keys(self::ATTRIBUTES),
                array_values(self::ATTRIBUTES),
            ),
        );

        return new Response(
            SamlId::generate(),
            $now,
            new Issuer(BINDINGS . '/idp'),
            $acs,
            $accepted->request->id,
            new Status(StatusCode::Success),
            $assertion,
        );
    }

    /**
     * This package's answer to an accepted LogoutRequest, to for-bindings's single logout service for HTTP-Redirect.
     */
    private function logoutResponseTo(LogoutRequest $request, ServiceProvider $sp): LogoutResponse
    {
        $endpoint = $this->endpoint($sp->singleLogoutServices, 'the single logout service of for-bindings');

        return new LogoutResponse(
            SamlId::generate(),
            $this->second(),
            new Issuer(BINDINGS . '/idp'),
            $endpoint->responseLocation ?? $endpoint->location,
            $request->id,
            new Status(StatusCode::Success),
        );
    }

    /**
     * The model's AuthnRequest to the identity provider's single sign-on service for HTTP-Redirect.
     */
    private function authnRequestTo(IdentityProvider $idp, Variant $variant): AuthnRequest
    {
        return new AuthnRequest(
            SamlId::generate(),
            $this->second(),
            new Issuer($variant->entityId()),
            $this->endpoint($idp->singleSignOnServices, 'the single sign-on service of the identity provider')->location,
            $variant->acs(),
            null,
            Binding::HttpPost->value,
            new NameIdPolicy(NameIdFormat::Transient->value, null, true),
        );
    }

    /**
     * The model's LogoutRequest for the session an accepted response opened, to the identity provider's single logout
     * service for HTTP-Redirect.
     */
    private function logoutRequestTo(IdentityProvider $idp, Variant $variant, AcceptedAssertion $accepted): LogoutRequest
    {
        $sessionIndex = $accepted->assertion->authnStatement->sessionIndex;

        return new LogoutRequest(
            SamlId::generate(),
            $this->second(),
            new Issuer($variant->entityId()),
            $this->endpoint($idp->singleLogoutServices, 'the single logout service of the identity provider')->location,
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
     * What for-bindings holds of its session (installation/sp/session.php).
     *
     * @return array<string, mixed>
     */
    private function session(Browser $browser): array
    {
        $session = json_decode($browser->get(SESSION)->body, true);

        return is_array($session) ? $session : throw new RuntimeException('session.php answered no JSON');
    }

    /**
     * The endpoint of $endpoints for HTTP-Redirect, the binding this package's judge plays.
     *
     * @param list<Endpoint> $endpoints
     */
    private function endpoint(array $endpoints, string $what): Endpoint
    {
        foreach ($endpoints as $endpoint) {
            if ($endpoint->binding === Binding::HttpRedirect) {
                return $endpoint;
            }
        }

        throw new RuntimeException(sprintf('%s is not published for HTTP-Redirect', $what));
    }

    private function reader(): MetadataReader
    {
        return new MetadataReader(SamlLoader::create(), $this->clock);
    }

    /**
     * Now, to the second: the writers write times to the second, and the documents say what the objects hold.
     */
    private function second(): DateTimeImmutable
    {
        $now = $this->clock->now();

        return $now->setTime((int) $now->format('H'), (int) $now->format('i'), (int) $now->format('s'));
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

$run = simplesamlphp_run($argv);
if (! is_dir(__DIR__ . '/written')) {
    mkdir(__DIR__ . '/written');
}
$exchange = new Exchange($run, __DIR__ . '/written', __DIR__ . '/../../Fixture/keys');

// RelayStates of 80 bytes, the bound of SAML Bindings §3.4.3, with a space and a "~", whose escaping differs between
// RFC 3986 and urlencode().
$eighty = str_pad('bindings ~ 80 bytes ', 80, '0123456789');
$variants = [
    new Variant('sp', 'its logout signed under sign.logout', Binding::HttpRedirect, true, 'bindings login ~', 'bindings logout ~'),
    new Variant('sp-defaults', 'its logout under SimpleSAMLphp\'s defaults', Binding::HttpRedirect, false, $eighty, null),
    new Variant('sp-post', 'its single logout service over HTTP-POST, its logout signed under sign.logout', Binding::HttpPost, true, null, $eighty),
];
$exchange->writeMetadata($variants);

$idp = $run->step('the identity provider\'s metadata, read live', static fn (): IdentityProvider => $exchange->identityProviderLive());
if ($idp instanceof IdentityProvider) {
    foreach ($variants as $index => $variant) {
        $login = $run->step(
            sprintf('this package as service provider %s, %s: login', $variant->name, $variant->what),
            static fn (): array => $exchange->loginAtTheIdentityProvider($variant, $idp, $index === 0),
        );
        if (! is_array($login)) {
            continue;
        }
        if ($index === 0) {
            $run->step(
                'probes: the identity provider and a LogoutRequest of this package changed after signing',
                static fn () => $exchange->probeLogoutRequests($login[0], $login[1], $idp, $variant),
            );
        }
        $run->step(
            sprintf('this package as service provider %s: logout', $variant->name),
            static fn () => $exchange->logoutAtTheIdentityProvider($variant, $login[0], $login[1], $idp),
        );
    }
    $run->step(
        'probes: the identity provider and an AuthnRequest of this package changed after signing',
        static fn () => $exchange->probeAuthnRequests($idp, $variants[0]),
    );
}

$login = $run->step(
    'this package as identity provider, for-bindings in front, the response with its signed assertion: login',
    static fn (): array => $exchange->loginAtThePackage(SignedParts::Assertion, true),
);
if (is_array($login)) {
    $run->step(
        'this package as identity provider: logout, with the probes of a LogoutResponse changed after signing',
        static fn () => $exchange->logoutAtThePackage($login[0], $login[1], $login[2], true, true),
    );
}
$login = $run->step(
    'this package as identity provider, the response signed over its signed assertion: login',
    static fn (): array => $exchange->loginAtThePackage(SignedParts::AssertionAndResponse, false),
);
if (is_array($login)) {
    $run->step(
        'this package as identity provider: logout',
        static fn () => $exchange->logoutAtThePackage($login[0], $login[1], $login[2], false, false),
    );
}

if ($idp instanceof IdentityProvider) {
    $run->step(
        'measure: the SigAlg the single sign-on service accepts',
        static fn () => $exchange->measureSignatureAlgorithms($idp, $variants[0]),
    );
    $run->step(
        'measure: how the identity provider decodes a space in a RelayState',
        static fn () => $exchange->measureRelayStateDecoding($idp, $variants[0]),
    );
}
$run->step(
    'measure: the RelayState for-bindings sends',
    static fn () => $exchange->measureServiceProviderRelayState(),
);

$run->exit();
