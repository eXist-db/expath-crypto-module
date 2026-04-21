xquery version "3.1";

(:~
 : Consolidated test suite for exist-crypto module.
 :
 : Adapted from:
 : - expath-crypto-module test suite (Claudius Teodorescu, LGPL-2.1)
 : - BaseX CryptoModuleTest (BaseX Team, BSD License)
 :
 : Tests are organized into sections:
 : - Hash tests: conformance with EXPath spec §2
 : - HMAC tests: conformance with EXPath spec §3, plus BaseX cross-compat
 : - Encrypt/Decrypt tests: conformance with EXPath spec §5-6, BaseX compat,
 :   and v6 backward compat (6-param arity)
 : - Signature tests: conformance with EXPath spec §7-8, v6 backward compat
 :
 : @see https://expath.org/spec/crypto
 : @see https://expath.org/spec/crypto/editor
 : @see https://docs.basex.org/main/Cryptographic_Functions
 :)

module namespace ct = "http://exist-db.org/ns/crypto/test";

import module namespace crypto = "http://expath.org/ns/crypto";

declare namespace test = "http://exist-db.org/xquery/xqsuite";

declare variable $ct:doc-1 := document {
<data>
  <a>1</a>
  <b>7</b>
  <c />
  <c />
</data>
};

(: ==================== Hash tests ==================== :)

declare
    %test:name("hash: MD5 string, base64")
    %test:assertEquals("use1oAoe8vIgnFgygz2OKw==")
function ct:hash-string-md5-base64() {
    crypto:hash("Short string for tests.", "MD5", "base64")
};

declare
    %test:name("hash: MD5 string, default format is base64")
    %test:assertEquals("use1oAoe8vIgnFgygz2OKw==")
function ct:hash-string-md5-default() {
    crypto:hash("Short string for tests.", "MD5")
};

declare
    %test:name("hash: SHA-1 string")
    %test:assertEquals("cV2wx17vo8eH2TaFRvCIIvJjNqU=")
function ct:hash-string-sha1() {
    crypto:hash("Short string for tests.", "SHA-1", "base64")
};

declare
    %test:name("hash: SHA-256 string")
    %test:assertEquals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=")
function ct:hash-string-sha256() {
    crypto:hash("Short string for tests.", "SHA-256", "base64")
};

declare
    %test:name("hash: SHA-256 string, hex")
    %test:assertEquals("13e0742732d18319b6fb5ac1f2a219a10d909fe24bc7024258e46fe3a7ca84c3")
function ct:hash-string-sha256-hex() {
    crypto:hash("Short string for tests.", "SHA-256", "hex")
};

declare
    %test:name("hash: SHA-384 string")
    %test:assertEquals("F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La")
function ct:hash-string-sha384() {
    crypto:hash("Short string for tests.", "SHA-384", "base64")
};

declare
    %test:name("hash: SHA-512 string")
    %test:assertEquals("+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdMFZ0+/JFK2g==")
function ct:hash-string-sha512() {
    crypto:hash("Short string for tests.", "SHA-512", "base64")
};

declare
    %test:name("hash: XML node input")
    %test:assertEquals("xMpCOKC5I4INzFCab3WEmw==")
function ct:hash-xml-node() {
    crypto:hash($ct:doc-1/*/*[1], "MD5", "base64")
};

declare
    %test:name("hash: unsupported algorithm throws error")
    %test:assertError
function ct:hash-bad-algorithm() {
    crypto:hash("test", "SHA-17", "base64")
};

declare
    %test:name("hash: accepts bare algorithm name (SHA256 without hyphen)")
    %test:assertEquals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=")
function ct:hash-bare-algorithm() {
    crypto:hash("Short string for tests.", "SHA256", "base64")
};

(: ==================== HMAC tests ==================== :)

(: --- Old module compatibility (PEM key, various algorithm name formats) --- :)

declare variable $ct:pem-key := "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAhPxBGln4YOcOGOxmRYEN8nzYHYvQx+PP8GnbJ+kW4f6HvH8WMAUa2lTB6gib
LzJGezhqkMy8NT8ogVz8xbra3AyK/IBDzXpWtPhSxVOCo6hJfTjj7wX3E2AVN9CTUOYrS/3iSu1q
/6MoB6MDIj8wV0HO1ujXqEip45UgVl+xRVtU+1wiJQ7Gc8GEEyHVtK/X4joiyCEebJhFsI42Z9e4
aETI/XOaLszyEQeipMRlyznpRL2x0chz+yj7KuwiMqBZmPYyeWBsbldW8xREwnHEyko5GWc6wkEi
vgFwzKaZWo2ct3pmZ9vwXKecAxbeJbyJQl/PDfSnqcwyhL6pOaSAuQIDAQABAoIBAHo5hnR7wIb/
lbteetjitjjqeY8eU/OD9DfYcu6Jkth/Ia4jd/cGmhmU0O0Sn96O7KyPu5H+OfUOaWIMXt400LZy
aMON98NA77RAj4KBMI7OO0z2Hrgu2Vlbc+TqtJskESM04ulOsIroIAB02Ip/XSS1fS+UrbEjp9Fd
3GzGYp2E6IF/YtTXMiqgdrZVAoDPtxiMR/1KXuETiBkeMxPvXfgePXLi/rYBDcecmfsCEzDX8RZV
xLoPKFxuLaIrzdVhGVHwp88fB57OufLytmuvro71FNrFzcIO88NyDpEQVnsBadm9Ir0mb5uhYq9j
YV444b2Gra0/onJm7e/zRUSSJGkCgYEA67Q8gBSADrkc0UCypjnFV8WWCQJBPspb9Vnf2MJi5aYM
U5Sa/2H+tNoY+fJoa/eDSu1jeAn71TDcXZizihj3IT8gVdoXSncbcTulxEnaOi85Q2uKfSia16rX
d+MufjJ4UDC7vR/Ve+zIQOxpzBmcFO5cMnLS3mJdpWSdS7DyQpMCgYEAkG+6udsQ02GEKaJZl2mi
XBqe4Rh187sDCwiqSO5ItS4jUg1xF1cn1PuF2nvjztZyEsaKKYdiqekEQv3jA6gRsWFvRi/abFN3
zau/5M42v7H1cgU7m+FsDywhN5IRAmGfEyL/2wpKuZ6lD2qqhGkXmxqyEqgmEClyIwxJKHWiAwMC
gYBCJK8Bpj8VYp8SnZxEh1u4uMrUtlxG2ZSasmDdvBbyqPk2jzI7zm0ipT1zDrJ88dVXNmy+Z9bS
ycZdQZfIfh8DpmpVjUER9YCu8vUeszbZMx1XrRsM6lMhiGC01PzcDx+yKSrV9NP81cKQbYd27gzd
1tHqmkxQebwbyLNXZU1mnwKBgDpuiPsBbdgmHkJ9pIMFwCJEvrvPmoBEyuFe2wzwIUfy52UdfP/1
SW73ZlpSPoIB7Vo9Kc3NMJQOaaP0dC+Zgbbh9RNO7q1eQxxYfCRDbJC2nNZI2amhU4b70mBZ3jm5
ZpJmWV2y1zIqxRnsjBlPLraX4Sx9DBEDw2H8aWhN1oIjAoGBANc0gizRHGfOK2UASXskuO5Ueias
6z0V7J/m93E7wK8IQHcZXGloy8S9QSX6uAqe48ZDVCZGPxqq7TppT+P9WsdqkXqxR7M/KLa+7Y6C
s1tkDtD9uOJN6CsLuVjfuo4ZT5SwC7pq842aQrqJveKWKdzEorQjWKeN8OM2wzEMs0P1
-----END RSA PRIVATE KEY-----";

declare
    %test:name("hmac: MD5, base64 (old module compat)")
    %test:assertEquals("l4MY6Yosjo7W60VJeXB/PQ==")
function ct:hmac-md5-base64() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HMAC-MD5", "base64")
};

declare
    %test:name("hmac: MD5, default format is base64")
    %test:assertEquals("l4MY6Yosjo7W60VJeXB/PQ==")
function ct:hmac-md5-default() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HMAC-MD5")
};

declare
    %test:name("hmac: SHA-1 (HmacSha1 name format)")
    %test:assertEquals("55LyDq7GFnqijauK4CQWR4AqyZk=")
function ct:hmac-sha1-base64() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HmacSha1", "base64")
};

declare
    %test:name("hmac: SHA-1 (HMAC-SHA-1 name format, default encoding)")
    %test:assertEquals("55LyDq7GFnqijauK4CQWR4AqyZk=")
function ct:hmac-sha1-default() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HMAC-SHA-1")
};

declare
    %test:name("hmac: SHA-256")
    %test:assertEquals("FfZidcLEUg4oJLIZfw6xHlPMz8KPHxo2liaBKgLfcOE=")
function ct:hmac-sha256-base64() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HmacSha256", "base64")
};

declare
    %test:name("hmac: SHA-384")
    %test:assertEquals("RRirKZTmx+cG8EXvgrRnpYFPEPYXaZBirY+LFmiUBAK61LCryDsL4clFRG5/BcBr")
function ct:hmac-sha384-base64() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HMAC-SHA-384", "base64")
};

declare
    %test:name("hmac: SHA-512")
    %test:assertEquals("z9MtEpBXxO5bKmsXJWfKsZ4v+RduKU89Y95H2HMGQEwHGefWmewNNQ7urZVuWEU5aeRRdO7G7j0QlcLYv1pkrg==")
function ct:hmac-sha512-base64() {
    crypto:hmac("Short string for tests.", $ct:pem-key, "HMAC-SHA-512", "base64")
};

declare
    %test:name("hmac: AWS S3 REST authentication pattern")
    %test:assertEquals("ggrrPVimvAlDa9xalO4+S87TKJY=")
function ct:hmac-aws-rest() {
    let $string-to-hash := string-join(
        ("PUT","c8fdb181845a4ca6b8fec737b3581d76","text/html",
         "Thu, 17 Nov 2005 18:49:58 GMT","x-amz-magic:password",
         "x-amz-meta-author:foo@bar.com","/quotes/nelson"),
        codepoints-to-string(10))
    let $private-key := "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"
    return
        crypto:hmac($string-to-hash, $private-key, "HMAC-SHA-1", "base64")
};

(: --- BaseX cross-compatibility (simple key, lowercase algorithm names) --- :)

declare
    %test:name("hmac: BaseX compat — MD5 base64")
    %test:assertEquals("TkdI5itGNSH2d1+/khI0tQ==")
function ct:hmac-basex-md5-base64() {
    crypto:hmac("message", "key", "md5", "base64")
};

declare
    %test:name("hmac: BaseX compat — MD5 hex")
    %test:assertEquals("4e4748e62b463521f6775fbf921234b5")
function ct:hmac-basex-md5-hex() {
    crypto:hmac("message", "key", "md5", "hex")
};

declare
    %test:name("hmac: BaseX compat — SHA256 base64")
    %test:assertEquals("bp7ym3X//Ft6uuUn1Y/a2y/kLnIZARl2kXNDBl9Y7Uo=")
function ct:hmac-basex-sha256-base64() {
    crypto:hmac("message", "key", "sha256", "base64")
};

declare
    %test:name("hmac: BaseX compat — SHA256 hex")
    %test:assertEquals("6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a")
function ct:hmac-basex-sha256-hex() {
    crypto:hmac("message", "key", "sha256", "hex")
};

declare
    %test:name("hmac: BaseX compat — SHA512 base64")
    %test:assertEquals("5Hc4TXyiKd0UJuZLY+vy0269bX5mmmc1Qk5y6mwB0/i1brOcNtgjL1QnmZuNGj+c0RKPxp9NdbQ0IWgQ+jZ+mA==")
function ct:hmac-basex-sha512-base64() {
    crypto:hmac("message", "key", "sha512", "base64")
};

(: ==================== Encrypt/Decrypt tests ==================== :)

declare
    %test:name("encrypt/decrypt: AES round-trip (4-param, BaseX compat)")
    %test:assertEquals("messagemessagemessagemessagemessagemessagemessage")
function ct:encrypt-decrypt-aes-4param() {
    let $msg := "messagemessagemessagemessagemessagemessagemessage"
    let $key := "abababababababab"
    let $enc := crypto:encrypt($msg, "symmetric", $key, "AES")
    return crypto:decrypt($enc, "symmetric", $key, "AES")
};

declare
    %test:name("encrypt/decrypt: DES round-trip (4-param, BaseX compat)")
    %test:assertEquals("messagemessagemessagemessagemessagemessagemessage")
function ct:encrypt-decrypt-des-4param() {
    let $msg := "messagemessagemessagemessagemessagemessagemessage"
    let $key := "aaabbbaa"
    let $enc := crypto:encrypt($msg, "symmetric", $key, "DES")
    return crypto:decrypt($enc, "symmetric", $key, "DES")
};

declare
    %test:name("encrypt/decrypt: AES round-trip (6-param, old module compat)")
    %test:assertEquals("Short string for tests.")
function ct:encrypt-decrypt-aes-6param() {
    let $iv := "abcdefghijklmnop"
    let $enc := crypto:encrypt("Short string for tests.", "symmetric", "1234567890123456", "AES", $iv, "")
    return crypto:decrypt($enc, "symmetric", "1234567890123456", "AES", $iv, "")
};

declare
    %test:name("encrypt: produces different output each time (random IV)")
    %test:assertFalse
function ct:encrypt-random-iv() {
    let $key := "0123456789abcdef"
    let $e1 := crypto:encrypt("test", "symmetric", $key, "AES")
    let $e2 := crypto:encrypt("test", "symmetric", $key, "AES")
    return $e1 = $e2
};

declare
    %test:name("encrypt: unsupported type throws error")
    %test:assertError
function ct:encrypt-bad-type() {
    crypto:encrypt("test", "asymmetric", "key", "AES")
};

declare
    %test:name("encrypt/decrypt: unicode data")
    %test:assertEquals("Hallo Welt! Привет мир! 你好世界！")
function ct:encrypt-decrypt-unicode() {
    let $msg := "Hallo Welt! Привет мир! 你好世界！"
    let $key := "0123456789abcdef"
    let $enc := crypto:encrypt($msg, "symmetric", $key, "AES")
    return crypto:decrypt($enc, "symmetric", $key, "AES")
};

(: ==================== XML Digital Signature tests ==================== :)

declare
    %test:name("signature: generate and validate enveloped (6-param)")
    %test:assertTrue
function ct:signature-enveloped-6param() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
    return crypto:validate-signature($signed)
};

declare
    %test:name("signature: generate and validate enveloping")
    %test:pending("enveloping signature validation needs investigation")
    %test:assertTrue
function ct:signature-enveloping() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "inclusive", "SHA256", "RSA_SHA256", "dsig", "enveloping")
    return crypto:validate-signature($signed)
};

declare
    %test:name("signature: signed document contains Signature element")
    %test:assertEquals("Signature")
function ct:signature-element-exists() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
    return local-name($signed//*[local-name() = 'Signature'])
};

declare
    %test:name("signature: tampered document fails validation")
    %test:assertFalse
function ct:signature-tampered-fails() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
    (: Tamper with the document by changing a value :)
    let $tampered := document {
        element data {
            $signed/data/@*,
            element a { "TAMPERED" },
            $signed/data/*[position() > 1]
        }
    }
    return crypto:validate-signature($tampered)
};

declare
    %test:name("signature: 7-param with XPath expression")
    %test:assertTrue
function ct:signature-7param-xpath() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped", "/")
    return crypto:validate-signature($signed)
};

declare
    %test:name("signature: exclusive canonicalization")
    %test:assertTrue
function ct:signature-exclusive-c14n() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "exclusive", "SHA256", "RSA_SHA256", "dsig", "enveloped")
    return crypto:validate-signature($signed)
};

declare
    %test:name("signature: inclusive-with-comments canonicalization")
    %test:assertTrue
function ct:signature-inclusive-with-comments() {
    let $signed := crypto:generate-signature(
        $ct:doc-1, "inclusive-with-comments", "SHA256", "RSA_SHA256", "ds", "enveloped")
    return crypto:validate-signature($signed)
};

declare
    %test:name("signature: unsupported digest throws error")
    %test:assertError
function ct:signature-bad-digest() {
    crypto:generate-signature($ct:doc-1, "exclusive", "MD5", "RSA_SHA1", "dsig", "enveloped")
};

declare
    %test:name("validate-signature: no signature element throws error")
    %test:assertError
function ct:validate-no-signature() {
    crypto:validate-signature($ct:doc-1)
};
