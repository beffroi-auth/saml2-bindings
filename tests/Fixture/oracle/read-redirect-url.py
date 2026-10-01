"""Reads a signed HTTP-Redirect URL as the OpenSSL oracle needs it (spec/bindings.md section 9.1), with Python alone.

Usage: python3 tests/Fixture/oracle/read-redirect-url.py <file.url> <directory>

From the query of the URL, what follows its first "?", split on "&" and each segment on its first "=", it takes the
raw values of the parameters of the binding by name, whatever their order, and writes into <directory>:

- octets: the octets of SAML Bindings section 3.4.4.1, built here from those raw values, still percent-encoded:
  SAMLRequest= or SAMLResponse= and its value, then &RelayState= and its value when the URL carries one, then
  &SigAlg= and its value;
- signature: the value of Signature, percent-decoded, then base64-decoded with the alphabet of RFC 4648;
- sigalg: the value of SigAlg, percent-decoded;
- message.xml: the value of the message parameter, percent-decoded, base64-decoded, then inflated by zlib as raw
  DEFLATE (RFC 1951, wbits -15), the stream complete and nothing after it.

Nothing here is PHP: the percent-decoding is urllib's, the base64 and the inflation Python's own. Any other shape of
the URL is an error.
"""

import base64
import binascii
import sys
import zlib
from urllib.parse import unquote_to_bytes

PARAMETERS = ('SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature', 'SAMLEncoding')


def fail(message):
    sys.stderr.write(message + '\n')
    sys.exit(1)


def parameters(url):
    """The raw value of each parameter of the binding the query of the URL carries, by name."""
    if '#' in url:
        fail('The URL holds a fragment.')
    if '?' not in url:
        fail('The URL holds no query.')
    raw = {}
    for segment in url.split('?', 1)[1].split('&'):
        name, separator, value = segment.partition('=')
        if name not in PARAMETERS:
            continue
        if name in raw:
            fail('The parameter ' + name + ' appears twice.')
        if separator != '=':
            fail('The parameter ' + name + ' has no "=".')
        raw[name] = value
    return raw


def base64_of(raw):
    """The bytes of a base64 value of the query, percent-decoded, the alphabet and the padding of RFC 4648 only."""
    try:
        return base64.b64decode(unquote_to_bytes(raw), validate=True)
    except binascii.Error as error:
        fail('A value is not base64: ' + str(error))


def inflated(deflated):
    """The message, inflated as one complete raw DEFLATE stream with nothing after it."""
    inflater = zlib.decompressobj(-15)
    try:
        message = inflater.decompress(deflated) + inflater.flush()
    except zlib.error as error:
        fail('The message is not raw DEFLATE: ' + str(error))
    if not inflater.eof or inflater.unused_data != b'':
        fail('The message is not one complete raw DEFLATE stream with nothing after it.')
    return message


def main(url_file, directory):
    with open(url_file, 'rb') as file:
        url = file.read().decode('ascii')
    raw = parameters(url)
    messages = [name for name in ('SAMLRequest', 'SAMLResponse') if name in raw]
    if len(messages) != 1:
        fail('The URL carries no message parameter, or both.')
    if 'SigAlg' not in raw or 'Signature' not in raw:
        fail('The URL is not signed.')
    message = messages[0]
    octets = message + '=' + raw[message]
    if 'RelayState' in raw:
        octets += '&RelayState=' + raw['RelayState']
    octets += '&SigAlg=' + raw['SigAlg']
    with open(directory + '/octets', 'wb') as file:
        file.write(octets.encode('ascii'))
    with open(directory + '/signature', 'wb') as file:
        file.write(base64_of(raw['Signature']))
    with open(directory + '/sigalg', 'wb') as file:
        file.write(unquote_to_bytes(raw['SigAlg']))
    with open(directory + '/message.xml', 'wb') as file:
        file.write(inflated(base64_of(raw[message])))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        fail('Usage: python3 read-redirect-url.py <file.url> <directory>')
    main(sys.argv[1], sys.argv[2])
