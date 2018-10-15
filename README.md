## eXist implementation for EXPath Cryptographic Module

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

For examples of usage, see the [folder in github](src/test/java/org/expath/exist/crypto/xquery/) or [the collection](/apps/expath-crypto/tests/unit-tests) when this library is installed in eXist.

### Unit Tests

Unit Tests can be found in '/apps/expath-crypto/tests/unit-tests' collection (when this library is installed in eXist).

For a simple test runner, showing description and status (passed / failed) for each unit test, go [here](tests/test-plan.xq).
