## eXist implementation for EXPath Cryptographic
Requirements:
*   [eXist-db](https:www.exist-db.org): `3.5.0`
*   [maven](https://maven.apache.org): `3.x` (for building from source only)

### Currently implemented functions
*   `crypto:hash()`
*   `crypto:hmac()` (only for xs:string data for now)
*   `crypto:encrypt()` (only for xs:string data and symmetric encryption for now)
*   `crypto:decrypt()` (only for xs:string data and symmetric decryption for now)
*   `crypto:generate-signature()` (only for XML data for now)
*   `crypto:validate-signature()` (only for XML data for now)

### Currently implemented algorithms
*   For `crypto:hash()`: "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512".
*   For `crypto:hmac()`: "HMAC-MD5", "HMAC-SHA-1", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512".

### Documentation
For the latest version of the specification for this module see [here](http://kuberam.ro/specs/expath/crypto/crypto.html). The implementation follows [this](http://expath.org/spec/crypto/editor) specification.

#### Examples of usage
```XQuery
xquery version "3.1";
import module namespace crypto="http://expath.org/ns/crypto";

let $data := 'mySecret'
return
crypto:hash($data, 'MD5')
```

For more examples of usage, see section Unit Tests.

#### Unit Tests
<!-- Missing info on how to run the tests -->
When this library is installed in exist-db, unit tests can be found at
<!-- not true, path does not exist -->
 `/apps/expath-crypto/tests/unit-tests`.

For a simple test runner, showing description and status (passed / failed) for each unit test, go to [tests/test-plan.xq](tests/test-plan.xq).

### Building from source
Clone or fork this repo to your local hard drive.
Then issue the following command from inside that folder:
`mvn clean package`
