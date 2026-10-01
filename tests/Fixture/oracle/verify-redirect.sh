#!/bin/sh
# Verifies with the OpenSSL command line, a verifier that is no SAML library (spec/bindings.md section 9.1), the
# detached signature of each signed HTTP-Redirect URL given, over the octets of SAML Bindings §3.4.4.1 that
# read-redirect-url.py builds from the URL's own parameters, under the certificate given; then checks that its message,
# inflated by Python's zlib, a decoder of raw DEFLATE that is not PHP's, is byte for byte the document written next to
# the URL, <name>.xml for <name>.url. A URL whose signature OpenSSL refuses, whose message is not that document, or
# that is not signed is an error. Run from the root of the repository, where openssl and python3 are installed
# (Alpine 3.22: apk add openssl python3):
#   sh tests/Fixture/oracle/verify-redirect.sh tests/Fixture/keys/sp-signing-certificate.pem <file.url>...
set -eu

certificate=$1
shift
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
openssl x509 -in "$certificate" -pubkey -noout > "$work/public.pem"
files=0
for url in "$@"; do
    expected="${url%.url}.xml"
    if [ ! -f "$url" ] || [ ! -f "$expected" ]; then
        echo "No file $url, or no $expected next to it." >&2
        exit 1
    fi
    python3 tests/Fixture/oracle/read-redirect-url.py "$url" "$work"
    # The six RSA schemes of dsig.md D-5, RFC 6931 §2.3: PKCS#1 v1.5, and RSASSA-PSS with MGF1 of the same digest and a
    # salt of the digest's length.
    case "$(cat "$work/sigalg")" in
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256') digest=sha256 padding=pkcs1 ;;
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384') digest=sha384 padding=pkcs1 ;;
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512') digest=sha512 padding=pkcs1 ;;
        'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1') digest=sha256 padding=pss ;;
        'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1') digest=sha384 padding=pss ;;
        'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1') digest=sha512 padding=pss ;;
        *)
            echo "$url: its SigAlg is none of the six RSA schemes." >&2
            exit 1
            ;;
    esac
    if [ "$padding" = pss ]; then
        openssl dgst "-$digest" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
            -sigopt "rsa_mgf1_md:$digest" -verify "$work/public.pem" -signature "$work/signature" "$work/octets"
    else
        openssl dgst "-$digest" -verify "$work/public.pem" -signature "$work/signature" "$work/octets"
    fi
    cmp "$work/message.xml" "$expected"
    echo "$url: $digest $padding signature verified by OpenSSL, message inflated by Python's zlib to $expected."
    files=$((files + 1))
done
if [ "$files" -eq 0 ]; then
    echo "No URL to verify." >&2
    exit 1
fi
echo "$files URLs verified under $certificate."
