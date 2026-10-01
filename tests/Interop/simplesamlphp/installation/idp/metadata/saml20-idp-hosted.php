<?php

// The hosted identity provider: its entity ID, its own signing pair and its authentication source, nothing else. Its
// single sign-on and single logout services are published as SimpleSAMLphp does by default, HTTP-Redirect alone
// (getGenerated() of src/SimpleSAML/Metadata/MetaDataStorageHandler.php): this package's judge plays that default,
// where saml2-model's published HTTP-POST too (its finding F-10). No signing option is set here: what it signs and
// what it verifies is set per service provider, in saml20-sp-remote.php.
$metadata['http://localhost:8091/simplesaml/module.php/saml/idp/metadata'] = [
    'host' => '__DEFAULT__',
    'privatekey' => 'idp.pem',
    'certificate' => 'idp.crt',
    'auth' => 'example-userpass',
];
