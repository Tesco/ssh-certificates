# ssh-certificates

A Java SDK for reading and creating SSH certificates and keys in RSA and ECDSA formats.

Open SSH has a proprietary format for certificates and public keys that is different to the more common X.509 format
used to TLS. This library addresses the lack of Java SDK / JDK support
for [Open SSH standards](https://www.openssh.com/specs.html).

Main features:
* reading / decoding Open SSH RSA and ECDSA Certifcates
* writing / encoding Open SSH RSA and ECDSA Certifcates
* reading / decoding Open SSH RSA and ECDSA Public Keys
* writing / encoding Open SSH RSA and ECDSA Public Keys
