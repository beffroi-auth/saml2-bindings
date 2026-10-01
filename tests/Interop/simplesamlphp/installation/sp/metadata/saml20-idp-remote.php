<?php

// The identity provider of http://localhost:8091, as its metadata publishes it.
$metadata['http://localhost:8091/simplesaml/module.php/saml/idp/metadata'] = [
    'SingleSignOnService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8091/simplesaml/module.php/saml/idp/singleSignOnService',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8091/simplesaml/module.php/saml/idp/singleLogout',
        ],
    ],
    'certificate' => 'idp.crt',
];

// This package's identity provider, once the exchange has written its metadata (tests/Interop/simplesamlphp/
// exchange.php): the XML the model's MetadataWriter wrote, read by SimpleSAMLphp's own parser, as it is; its
// WantAuthnRequestsSigned="true" becomes sign.authnrequest (SAMLParser::getMetadata20IdP()). The service provider that
// logs in there, for-bindings, carries its own settings (authsources.php).
$file = '/var/simplesamlphp/bindings/bindings-idp-metadata.xml';
if (is_file($file)) {
    foreach (\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString((string) file_get_contents($file)) as $entityId => $parser) {
        $metadata[$entityId] = $parser->getMetadata20IdP() ?? [];
    }
}
