# Security policy

This package decides, for an identity provider or a service provider, which message a query string or a form carries,
which octets the detached signature of HTTP-Redirect had to cover, and whether the model may hear that the binding
authenticated it: a flaw here is an authentication bypass in every application that trusts what the package hands
over.

## Reporting

Report privately through [GitHub security advisories](https://github.com/beffroi-php/saml2-bindings/security/advisories/new).
Do not open a public issue, do not discuss it in a pull request.

You will get an acknowledgement within 72 hours, and a fix or a mitigation plan as fast as the severity requires.
Credit is given in the advisory unless you prefer otherwise.

A flaw of the SAML model, the strict readers, the validators or the writers, belongs to
[`beffroi-php/saml2-model`](https://github.com/beffroi-php/saml2-model/security/advisories/new); one of the XML layer
below, the loader, the canonicalization, XML Signature or XML Encryption, to
[`beffroi-php/xml-security`](https://github.com/beffroi-php/xml-security/security/advisories/new). When you cannot tell
which package it belongs to, report it here.

## What is published

Every security fix ships with a GitHub Security Advisory and a CVE requested for it, so that `composer audit`,
Packagist and the advisory databases see it (`spec/bindings.md`, section 10).

## Scope

Anything in this repository: the receivers, the senders, the codecs, the tooling and the CI. The rules the package
enforces are the invariants B-1 to B-13 of `spec/bindings.md`, section 4; a way to defeat one of them with input,
without a code change, is a vulnerability: a message decoded from another parameter than the one the signature covers
(B-1), octets verified that are not those the sender signed (B-2), a `SigAlg` off the closed list accepted (B-3), a key
taken from the query string (B-4), a message the model hears authenticated by the binding without the signature holding
(B-5), an XML signature accepted over HTTP-Redirect (B-6), an input decoded or inflated past its bound (B-7), two
spellings of one value accepted (B-8), a `RelayState` given to the model (B-9). A refusal message that carries a value
of the input is one too (B-11).

Out of scope: a consumer that calls what section 8 of the specification bans, which the PHPStan rules of this
repository exist to prevent; one that hands the package a query string normalised by its framework, or rebuilt from
parsed parameters, instead of the raw one, states a wrong URL of arrival, or protects the integrity of its `RelayState`
by no means of its own (section 6.8); the page that posts the form, its escaping and its content security policy, which
are the consumer's (section 6.7).

## Supported versions

Until the first tagged release, `main` only. From `1.0.0`, the latest minor of the latest major.
