[![CI](https://github.com/eXist-db/expath-crypto-module/workflows/CI/badge.svg)](https://github.com/eXist-db/expath-crypto-module/actions?query=workflow%3ACI)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/6700c245da044962938994fc59a2ebdc)](https://app.codacy.com/gh/eXist-db/expath-crypto-module/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

# eXist-db implementation for EXPath Cryptographic Module

This is an eXist-db implementation of the [EXPath HTTP Crypto Module specification](http://expath.org/spec/crypto).
## Building from source

Requires:
* Java 1.8 or newer
* Maven 3.6 or newer

```bash
$ git clone https://github.com/eXist-db/expath-crypto-module.git
$ cd expath-crypto-module
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

### Security considerations

The crypto module is a security-sensitive library and operates on XML documents
that may come from untrusted sources. A few things to know when deploying or
auditing it:

* **XXE protection lives in this module, not in `conf.xml`.** eXist-db's
  `<validation>` configuration in `conf.xml` controls catalog resolution and
  validation mode, not entity processing. eXist hardens its *own* parsers by
  calling `setFeature("...external-general-entities", false)` etc. at each call
  site in Java code. The crypto module uses its own `DocumentBuilderFactory` /
  `SAXParserFactory` instances (centralised in
  `org.expath.exist.crypto.utils.SecureXmlParsers`), and **does not inherit**
  those settings. Both signature paths now refuse DOCTYPE declarations
  outright (`disallow-doctype-decl=true`), which is the OWASP-recommended
  baseline. A strict `conf.xml` does not, on its own, protect callers of
  `crypto:generate-signature` or `crypto:validate-signature` against XXE.

* **Signature algorithms are limited to SHA-1-based xmldsig methods**
  (`RSA_SHA1`, `DSA_SHA1`) by the underlying `crypto-java` library, which has
  not been updated to support SHA-256. JDK 17+ rejects these by default under
  `org.jcp.xml.dsig.secureValidation` — see the
  [JDK XML Signature security guide](https://docs.oracle.com/en/java/javase/21/security/java-xml-digital-signature-api-overview-and-tutorial.html)
  for the policy. Don't sign new documents with these algorithms in production.

* **Symmetric encryption uses CBC (or unprefixed `AES`, which defaults to ECB)
  without authentication.** There is no AEAD (e.g. AES-GCM) support, and the
  module performs no HMAC-then-encrypt or encrypt-then-HMAC pairing. Ciphertext
  integrity is the caller's responsibility — without it, CBC is vulnerable to
  padding-oracle attacks, and ECB leaks plaintext structure.

* **Constant-time comparison is the caller's responsibility.** XQuery's `=`
  operator is *not* constant-time. When comparing HMAC outputs or signature
  values, an attacker who can measure timing can recover bytes. There is no
  `crypto:verify-hmac` helper that compares in constant time; callers should
  treat HMAC verification as a known sharp edge.

If you find what you believe is a security issue, please follow the
[eXist-db security policy](https://github.com/eXist-db/exist/security/policy)
rather than opening a public issue.

### Unit Tests

Unit Tests use [XQSuite](https://exist-db.org/exist/apps/doc/xqsuite) and can be found in the [src/test/xquery/crypto folder](src/test/xquery/crypto/). 

To run tests:

```bash
$ mvn verify
```