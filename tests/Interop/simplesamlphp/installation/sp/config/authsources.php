<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, default-sp given its entity ID, its identity
// provider, its own signing pair, and signed authentication and logout requests.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['default-sp']['entityID'] = 'http://localhost:8092/simplesaml/module.php/saml/sp/metadata/default-sp';
$config['default-sp']['idp'] = 'http://localhost:8091/simplesaml/module.php/saml/idp/metadata';
$config['default-sp']['privatekey'] = 'sp.pem';
$config['default-sp']['certificate'] = 'sp.crt';
$config['default-sp']['sign.authnrequest'] = true;
$config['default-sp']['sign.logout'] = true;

// A second service provider, for the exchange with this package's identity provider (exchange.php): default-sp's
// settings, its own entity ID, this package's identity provider, and validate.logout, under which a logout message
// without a signature is refused (saml2-model's finding F-9); a query string that carries one is verified whatever the
// setting, unless it is false (Message::validateMessage()). Its single logout service keeps SimpleSAMLphp's default
// publication, HTTP-Redirect, where this package answers.
$config['for-bindings'] = [
    'saml:SP',
    'entityID' => 'http://localhost:8092/simplesaml/module.php/saml/sp/metadata/for-bindings',
    'idp' => 'http://localhost:8093/bindings/idp',
    'privatekey' => 'sp.pem',
    'certificate' => 'sp.crt',
    'sign.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,
];
