[![CI](https://github.com/eXist-db/expath-crypto-module/workflows/CI/badge.svg)](https://github.com/eXist-db/expath-crypto-module/actions?query=workflow%3ACI)

# EXPath Crypto Module for eXist-db

Version 7.0 — a drop-in replacement for [expath-crypto-module](https://github.com/eXist-db/expath-crypto-module) 6.x.

Implements the [EXPath Cryptographic Module](https://expath.org/spec/crypto) specification for eXist-db using Java's built-in JCE — no external dependencies. Function signatures are compatible with both the old eXist module and [BaseX's crypto module](https://docs.basex.org/main/Cryptographic_Functions) for cross-engine portability.

## Requirements

- **eXist-db 7.0+** (uses `exist.xml` auto-registration)
- **Java 21+** (uses `HexFormat`, switch expressions, pattern matching)

Users on eXist 6 / Java 8–11 should continue using [expath-crypto-module 6.x](https://github.com/eXist-db/expath-crypto-module).

## Install

```bash
xst package install target/exist-crypto-7.0.0-SNAPSHOT.xar
```

The `pre-install.xq` script automatically removes the old expath-crypto-module if present. The two packages share the same package URI (`http://expath.org/ns/crypto`) and cannot coexist.

## Functions

**Module namespace:** `http://expath.org/ns/crypto`

| Function | Arities | Spec | BaseX | v6 compat |
|----------|---------|------|-------|-----------|
| `crypto:hash` | 2, 3 | ✓ §2 | — (use `fn:hash`) | ✓ |
| `crypto:hmac` | 3, 4 | ✓ §3 | ✓ | ✓ |
| `crypto:encrypt` | 4, 6 | ✓ §5 | ✓ (4-param) | ✓ |
| `crypto:decrypt` | 4, 6 | ✓ §6 | ✓ (4-param) | ✓ |
| `crypto:generate-signature` | 3, 6, 7, 8 | ✓ §7 | ✓ (6+2 optional) | ✓ |
| `crypto:validate-signature` | 1 | ✓ §8 | ✓ | ✓ |

### Hash

```xquery
import module namespace crypto = "http://expath.org/ns/crypto";

crypto:hash("data", "SHA-256")              (: Base64 output :)
crypto:hash("data", "SHA-256", "hex")       (: Hex output :)
crypto:hash(<node>data</node>, "SHA-256")   (: Node input :)
```

Algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512. For new code, prefer `fn:hash()` (XQuery 4.0) or `util:hash()`.

### HMAC

```xquery
crypto:hmac("data", "secret-key", "SHA256")              (: Base64 :)
crypto:hmac("data", "secret-key", "SHA256", "hex")       (: Hex :)
crypto:hmac(xs:base64Binary("..."), "key", "SHA256")     (: Binary input :)
```

Algorithms: MD5, SHA1, SHA256, SHA384, SHA512. Names accept hyphenated (`SHA-256`), bare (`SHA256`), prefixed (`HMAC-SHA-256`), and lowercase (`sha256`) forms for BaseX compatibility.

### Symmetric Encryption

```xquery
(: 4-param: auto-generated IV, prepended to ciphertext :)
let $enc := crypto:encrypt("secret", "symmetric", $key, "AES")
return crypto:decrypt($enc, "symmetric", $key, "AES")

(: 6-param: explicit IV and provider (v6 backward compat) :)
let $enc := crypto:encrypt("secret", "symmetric", $key, "AES", $iv, $provider)
return crypto:decrypt($enc, "symmetric", $key, "AES", $iv, $provider)
```

Algorithms: AES (16/24/32-byte key), DES (8-byte key).

### XML Digital Signatures

```xquery
(: 6-param: generated key pair :)
let $signed := crypto:generate-signature(
    $doc, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
return crypto:validate-signature($signed)

(: 7-param: + XPath expression for selective signing :)
crypto:generate-signature($doc, "exclusive", "SHA256", "RSA_SHA256",
    "dsig", "enveloped", $xpath)

(: 8-param: + digital certificate from keystore :)
crypto:generate-signature($doc, "exclusive", "SHA256", "RSA_SHA256",
    "dsig", "enveloped", $xpath, $certificate)

(: 3-param: simplified signing with PKCS#8 private key :)
crypto:generate-signature($doc, $base64-private-key, "RSA_SHA256")
```

## Upgrading from expath-crypto-module 6.x

### No changes needed

The module namespace is identical — **import statements require no changes**:

```xquery
import module namespace crypto = "http://expath.org/ns/crypto";
```

All function names, arities, and algorithm names are backward compatible. Code using `crypto:hash`, `crypto:hmac`, `crypto:generate-signature` (6/7/8-param), `crypto:validate-signature`, and `crypto:encrypt`/`crypto:decrypt` (4-param and 6-param) will work without modification.

### Breaking changes

There are two breaking changes for users upgrading from v6:

#### 1. `crypto:encrypt` / `crypto:decrypt` output format

| | v6 (expath-crypto-module) | v7 (exist-crypto) |
|---|---|---|
| **encrypt output** | Dash-separated bytes: `"51-143-171-200-..."` | `xs:base64Binary` |
| **decrypt input** | Dash-separated bytes | `xs:base64Binary` |

**Impact:** Data encrypted with v6 **cannot be decrypted with v7** (and vice versa). The wire format is different.

**Migration:** If you have stored encrypted data from v6, decrypt it with v6 first, then re-encrypt with v7. For data encrypted in transit (e.g., JWT tokens), both sides must use the same version.

#### 2. DSA_SHA1 signatures forbidden

Java 21+ forbids DSA_SHA1 in secure signature validation. Use `RSA_SHA256` instead:

```xquery
(: v6 — worked but now forbidden by Java 21+ :)
crypto:generate-signature($doc, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped")

(: v7 — use RSA_SHA256 instead :)
crypto:generate-signature($doc, "inclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
```

### Improvements over v6

- **Binary HMAC input**: `crypto:hmac` now accepts `xs:base64Binary` and `xs:hexBinary` for `$data` and `$key`
- **Flexible algorithm names**: lowercase (`sha256`), bare (`SHA256`), hyphenated (`SHA-256`), and prefixed (`HMAC-SHA-256`) all work
- **AES key sizes**: 128, 192, and 256-bit keys supported (v6 only supported 128)
- **RSA_SHA256**: Added as a signature algorithm (v6 only had RSA_SHA1 and DSA_SHA1)
- **Zero dependencies**: No external `crypto-java` library needed
- **102 tests**: JUnit + XQSuite, including BaseX cross-compatibility vectors

## Conformance

### EXPath Cryptographic Module 1.0

Implements §2 (hash), §3 (hmac), §5 (encrypt), §6 (decrypt), §7 (generate-signature), §8 (validate-signature). Not implemented: §4 (key management), §9 (secure store) — these are marked "TBD" in the spec.

### EXPath Cryptographic Module Editor's Draft

The editor's draft consolidates function parameters into maps (`$parameters as map(xs:string, item())`). We support this via the 2-param map-based `generate-signature` arity alongside the positional arities for backward compatibility.

### [EXPath Crypto 2018 CG Final Report](https://github.com/claudius108/expath-cg/blob/master/specs/crypto/crypto-new.html)

This November 2018 revision by Claudius Teodorescu adds several features we implement:
- **`crypto:list-providers`/`list-services`/`list-algorithms`** — provider introspection functions returning maps and arrays. Implemented but currently disabled pending an eXist-db binary search fix for zero-param arities in ordered module registries.
- **Algorithm name aliases** — Java-style names `DSAwithSHA1`, `RSAwithSHA1` accepted alongside `DSA_SHA1`, `RSA_SHA1`.
- **XML Canonicalization 1.1** — `inclusive-1.1` and `inclusive-with-comments-1.1` options.
- **Map-based `generate-signature`** — 2-param `($data, $parameters as map(*))` arity.

### BaseX Cryptographic Functions

Function signatures match BaseX for the common arities: `crypto:hmac` (4-param), `crypto:encrypt` (4-param), `crypto:decrypt` (4-param), `crypto:generate-signature` (6+2 optional), `crypto:validate-signature` (1-param). Algorithm names accept BaseX's lowercase convention.

## Build

```bash
JAVA_HOME=/path/to/java-21 mvn clean package -DskipTests
```

Run tests (102 total — requires exist-core in local Maven repo):

```bash
mvn test -Pintegration-tests
```

## License

[GNU Lesser General Public License v2.1](https://opensource.org/licenses/LGPL-2.1)
