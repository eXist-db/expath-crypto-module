[![CI](https://github.com/eXist-db/crypto-exist-java-lib/workflows/CI/badge.svg)](https://github.com/eXist-db/crypto-exist-java-lib/actions?query=workflow%3ACI)

# eXist-db implementation for EXPath Cryptographic Module

This is an eXist-db implementation of the [EXPath HTTP Crypto Module specification](http://expath.org/spec/crypto).
## Building from source

Requires:
* Java 1.8 or newer
* Maven 3.6 or newer

```bash
$ git clone https://github.com/eXist-db/crypto-exist-java-lib
$ cd crypto-exist-java-lib
$ mvn clean package
```

This will create a "expath-crypto-module-<version>.xar" file in the target folder. The .xar file can be uploaded to any eXist-db version > 5.3.0 via the Dashboard.
  
### Currently implemented functions

*   crypto:hash()
*   crypto:hmac() (only for xs:string data for now)
*   crypto:encrypt() (only for xs:string data and symmetric encryption for now)
*   crypto:decrypt() (only for xs:string data and symmetric decryption for now)
*   crypto:generate-signature() (only for XML data for now)
*   crypto:validate-signature() (only for XML data for now)

### Currently implemented algorithms

*   For crypto:hash(): "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512".
*   For crypto:hmac(): "HMAC-MD5", "HMAC-SHA-1", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512".

### Documentation

For the latest version of the specification for this module see [http://expath.org/spec/crypto/editor](http://expath.org/spec/crypto/editor).

The implementation follows this specification.

### Examples of usage

For examples of usage, see [this folder in github](src/test/java/org/expath/exist/crypto/xquery/) or [this collection](/apps/expath-crypto/tests/unit-tests) when this library is installed in eXist.

### Unit Tests

Unit Tests can be found in [this folder in github](src/test/java/org/expath/exist/crypto/xquery/) or in [this collection](/apps/expath-crypto/tests/unit-tests) when this library is installed in eXist.

When this library is installed in eXist, to get a simple test runner, showing description and status (passed / failed) for each unit test, go [here](/apps/expath-crypto/tests/test-plan.xq).
