<?php

// The service provider of http://localhost:8092, as its metadata publishes it.
$metadata['http://localhost:8092/simplesaml/module.php/saml/sp/metadata/default-sp'] = [
    'AssertionConsumerService' => [
        [
            'index' => 0,
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8092/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
        ],
    ],
    'certificate' => 'sp.crt',
];

// This package's service providers, once the exchange has written their metadata (tests/Interop/simplesamlphp/
// exchange.php): the XML the model's MetadataWriter wrote, read by SimpleSAMLphp's own parser, the one its XML
// metadata sources and its metarefresh module use. Its AuthnRequestsSigned="true" becomes validate.authnrequest
// (SAMLParser::getMetadata20SP()), under which the identity provider refuses an AuthnRequest without a signature; a
// query string that carries one is verified whatever the setting, unless it is false (Message::validateMessage()).
// Every entry facing this package adds validate.logout, under which a logout message without a signature is refused
// (saml2-model's finding F-9). What the identity provider signs over HTTP-Redirect differs by entry
// (Message::addRedirectSign()):
// - bindings/sp: sign.logout, its logout messages signed, which the model requires (M-2, saml2-model's finding F-1);
// - bindings/sp-defaults: nothing added, SimpleSAMLphp's default, its LogoutResponse unsigned;
// - bindings/sp-post: sign.logout, its single logout service published for HTTP-POST alone, where the identity provider
//   answers with a form.
$settings = [
    'http://localhost:8093/bindings/sp' => ['sign.logout' => true, 'validate.logout' => true],
    'http://localhost:8093/bindings/sp-defaults' => ['validate.logout' => true],
    'http://localhost:8093/bindings/sp-post' => ['sign.logout' => true, 'validate.logout' => true],
];
foreach (glob('/var/simplesamlphp/bindings/bindings-sp*-metadata.xml') ?: [] as $file) {
    foreach (\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString((string) file_get_contents($file)) as $entityId => $parser) {
        $metadata[$entityId] = ($settings[$entityId] ?? []) + ($parser->getMetadata20SP() ?? []);
    }
}
