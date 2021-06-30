xquery version "3.1";

(: An xqsuite edition of the original java tests in crypto-exist-java-lib :)

module namespace t="http://exist-db.org/xquery/test";

import module "http://expath.org/ns/crypto";

declare namespace test="http://exist-db.org/xquery/xqsuite";

declare variable $t:DOC-1 := document {
<data>
  <a>1</a>
  <b>7</b>
  <c />
  <c />
</data>
};

declare variable $t:PRIVATE_KEY_PEM := "-----BEGIN RSA PRIVATE KEY-----
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
    %test:setUp
function t:setup() {
    let $testCol := xmldb:create-collection("/db", "test")
    return
        (
            xmldb:store("/db/test", "doc-1.xml", $t:DOC-1),
            (: TODO adjust path to keystore.ks :)
            xmldb:store-files-from-pattern("/db/test", "/Users/joe/workspace/crypto-exist-java-lib/src/test/resources/org/expath/exist/crypto", "*.ks")
        )
};

declare
    %test:tearDown
function t:tearDown() {
    xmldb:remove("/db/test")
};

(:~ Authenticating a REST Request as needed by S3 Amazon Web Service. :)
declare
    %test:name("AWS REST request")
    %test:assertEquals("jZNOcbfWmD/A/f3hSvVzXZjM2HU=")
function t:AwsRestRequest() {
    let $string-to-hash := "PUT
c8fdb181845a4ca6b8fec737b3581d76
text/html
Thu, 17 Nov 2005 18:49:58 GMT
x-amz-magic:password
x-amz-meta-author:foo@bar.com
/quotes/nelson"
    let $private-key := "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"
    return
        crypto:hmac($string-to-hash, $private-key, "HMAC-SHA-1", "base64")
};

(:~ Authenticating a REST Request as needed by S3 Amazon Web Service with default format. :)
declare
    %test:name("AWS REST request, default format")
    %test:assertEquals("jZNOcbfWmD/A/f3hSvVzXZjM2HU=")
function t:AwsRestRequestWithDefaultFormat() {
    let $string-to-hash := "PUT
c8fdb181845a4ca6b8fec737b3581d76
text/html
Thu, 17 Nov 2005 18:49:58 GMT
x-amz-magic:abracadabra
x-amz-meta-author:foo@bar.com
/quotes/nelson"
    let $private-key := "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"
    return
        crypto:hmac($string-to-hash, $private-key, "HMAC-SHA-1")
};

(:~ Symmetric decryption of a string with AES/CBC/PKCS5Padding transformation, and 128 bytes key. :)
declare
    %test:name("Symmetric decryption of string, AES/CBC/PKCS5Padding")
    %test:assertEquals("Short string for tests.")
function t:decryptStringWithAesSymmetricKeyCbcMode() {
    let $iv := crypto:hash("initialization vector", "MD5", "base64")
    return
        crypto:decrypt("51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54", "symmetric", "1234567890123456", "AES/CBC/PKCS5Padding", $iv, "SunJCE")
};

(:~ Symmetric decryption of a string with AES/CBC/PKCS5Padding transformation, 128 bytes key, and default provider. :)
declare
    %test:name("Symmetric decryption of string, AES/CBC/PKCS5Padding, default provider")
    %test:assertEquals("Short string for tests.")
function t:decryptStringWithAesSymmetricKeyCbcModeDefaultProvider() {
    let $iv := crypto:hash("initialization vector", "MD5", "base64")
    return
        crypto:decrypt("51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54", "symmetric", "1234567890123456", "AES/CBC/PKCS5Padding", $iv, ())
};

(:~ Symmetric decryption of a string with AES transformation (implicit ECB mode), and 128 bytes key. :)
declare
    %test:name("Symmetric decryption of string, AES")
    %test:assertEquals("Short string for tests.")
function t:decryptStringWithAesSymmetricKeyEcbMode() {
    crypto:decrypt("222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87", "symmetric", "1234567890123456", "AES", (), "SunJCE")
};

(:~ Symmetric encryption of a string with AES/CBC/PKCS5Padding transformation, and 128 bytes key. :)
declare
    %test:name("Symmetric encryption of string, AES/CBC/PKCS5Padding")
    %test:assertEquals("51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54")
function t:encryptStringWithAesSymmetricKeyCbcMode() {
    let $iv := crypto:hash("initialization vector", "MD5", "base64")
    return
        crypto:encrypt("Short string for tests.", "symmetric", "1234567890123456", "AES/CBC/PKCS5Padding", $iv, "SunJCE")
};

(:~ Symmetric encryption of a string with AES/CBC/PKCS5Padding transformation, 128 bytes key, and default provider. :)
declare
    %test:name("Symmetric encryption of string, AES/CBC/PKCS5Padding, default provider")
    %test:assertEquals("51-143-171-200-187-20-34-252-231-243-254-42-36-13-9-123-191-251-243-42-3-238-193-13-155-168-139-67-135-3-143-54")
function t:encryptStringWithAesSymmetricKeyCbcModeDefaultProvider() {
    let $iv := crypto:hash("initialization vector", "MD5", "base64")
    return
        crypto:encrypt("Short string for tests.", "symmetric", "1234567890123456", "AES/CBC/PKCS5Padding", $iv, "")
};

(:~ Symmetric encryption of a string with AES transformation (implicit ECB mode), and 128 bytes key. :)
declare
    %test:name("Symmetric encryption of string, AES")
    %test:assertEquals("222-157-20-54-132-99-46-30-73-43-253-148-61-155-86-141-51-56-40-42-31-168-189-56-236-102-58-237-175-171-9-87")
function t:encryptStringWithAesSymmetricKeyEcbMode() {
    crypto:encrypt("Short string for tests.", "symmetric", "1234567890123456", "AES", (), "SunJCE")
};

(:~ Symmetric encryption of a string with AES/CBC/PKCS5Padding transformation, and wrong key. :)
declare
    %test:name("Symmetric encryption of string, AES/CBC/PKCS5Padding, wrong key")
    %test:assertError("err:CX19: The secret key is invalid")
function t:encryptStringWithAesWrongSymmetricKeyCbcMode() {
    let $iv := crypto:hash("initialization vector", "MD5", "")
    return
        crypto:encrypt("Short string for tests.", "symmetric", "12345678901234567", "AES/CBC/PKCS5Padding", $iv, "SunJCE")
};

(:~ Symmetric encryption of a string with AES/CBC/PKCS5Padding transformation, wrong key, and default provider. :)
declare
    %test:name("Symmetric encryption of string, AES/CBC/PKCS5Padding, wrong key, default provider")
    %test:assertEquals("err:CX19: The secret key is invalid")
function t:encryptStringWithAesWrongSymmetricKeyCbcModeDefaultProvider() {
    let $iv := crypto:hash("initialization vector", "MD5", "")
    return
        crypto:encrypt("Short string for tests.", "symmetric", "12345678901234567", "AES/CBC/PKCS5Padding", $iv, ())
};

(:~ Generate an enveloped digital signature for an XML document by using the following parameters:
 : 'SHA1' canonicalization algorithm, 
 : 'DSA_SHA1' signature algorithm,
 : 'dsig' signature namespace prefix, 
 : and an X509 certificate. :)
declare
    %test:name("Generate enveloped digital signature")
    %test:assertEquals("/KaCzo4Syrom78z3EQ5SbbB4sF7ey80etKII864WF64B81uRpH5t9jQTxeEu0ImbzRMqzVDZkVG9xD7nN1kuFw==")
function t:generateEnvelopedDigitalSignature() {
    let $sample-doc := $t:DOC-1
    let $certificate-details :=
        <digital-certificate>
            <keystore-type>JKS</keystore-type>
            <keystore-password>ab987c</keystore-password>
            <key-alias>eXist</key-alias>
            <private-key-password>kpi135</private-key-password>
            <keystore-uri>xmldb:///db/test/keystore.ks</keystore-uri>
        </digital-certificate>
    let $signed-doc := crypto:generate-signature($sample-doc, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped")
    return
        $signed-doc//*[local-name() = 'P']/text()
};

(:~ Hashing a binary by using 'MD5' algorithm. :)
declare
    %test:name("'MD5' hashing for binary")
    %test:assertEquals("UI/aOJodA6gtJPitQ6xcJA==")
function t:hashBinaryWithMd5() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "MD5", "base64")
};

(:~ Hashing a binary by using 'MD5' algorithm and the default format. :)
declare
    %test:name("'MD5' hashing for binary, default format")
    %test:assertEquals("UI/aOJodA6gtJPitQ6xcJA==")
function t:hashBinaryWithMd5AndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "MD5", ())
};

(:~ Hashing a binary by using 'SHA-1' algorithm. :)
declare
    %test:name("'SHA-1' hashing for binary")
    %test:assertEquals("GyscHvnJKxInsBLgSg/FRAmQXYU=")
function t:hashBinaryWithSha1() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-1", "base64")
};

(:~ Hashing a binary by using 'SHA-1' algorithm and the default format. :)
declare
    %test:name("'SHA-1' hashing for binary, default format")
    %test:assertEquals("GyscHvnJKxInsBLgSg/FRAmQXYU=")
function t:hashBinaryWithSha1AndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-1", ())
};

(:~ Hashing a binary by using 'SHA-256' algorithm. :)
declare
    %test:name("'SHA-256' hashing for binary")
    %test:assertEquals("37JiNBym250ye3aUJ04RaZg3SFSP03qJ8FR/I1JckVI=")
function t:hashBinaryWithSha256() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-256", "base64")
};

(:~ Hashing a binary by using 'SHA-256' algorithm and the default format. :)
declare
    %test:name("'SHA-256' hashing for binary, default format")
    %test:assertEquals("37JiNBym250ye3aUJ04RaZg3SFSP03qJ8FR/I1JckVI=")
function t:hashBinaryWithSha256AndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-256", ())
};

(:~ Hashing a binary by using 'SHA-384' algorithm. :)
declare
    %test:name("'SHA-384' hashing for binary")
    %test:assertEquals("DcQ3caBftiQCIQn96Pr8PC2vzs17Re0tZ8/CZnOoucu/N+818uqAXxR7l9oxYgoW")
function t:hashBinaryWithSha384() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-384", "base64")
};

(:~ Hashing a string by using 'SHA-384' algorithm and the default format. :)
declare
    %test:name("'SHA-384' hashing for binary, default format")
    %test:assertEquals("DcQ3caBftiQCIQn96Pr8PC2vzs17Re0tZ8/CZnOoucu/N+818uqAXxR7l9oxYgoW")
function t:hashBinaryWithSha384AndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-384", ())
};

(:~ Hashing a binary by using 'SHA-512' algorithm. :)
declare
    %test:name("'SHA-512' hashing for binary")
    %test:assertEquals("Be+hlGy9TNibbaE+6DA2gu6kNj2GS+7b4egFcJDMzQSFQiGgFtTh/mD61ta4pDvc+jqHFlqOyJLHirkROd86Mw==")
function t:hashBinaryWithSha512() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-512", "base64")
};

(:~ Hashing a binary by using 'SHA-512' algorithm and the default format. :)
declare
    %test:name("'SHA-512' hashing for binary, default format")
    %test:assertEquals("Be+hlGy9TNibbaE+6DA2gu6kNj2GS+7b4egFcJDMzQSFQiGgFtTh/mD61ta4pDvc+jqHFlqOyJLHirkROd86Mw==")
function t:hashBinaryWithSha512AndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-512", ())
};

(:~ Hashing a binary with a wrong algorithm. Test will pass if the correct error is thrown. :)
declare
    %test:name("Hash binary with wrong algorithm")
    %test:assertError("err:CX21: The algorithm is not supported.")
function t:hashBinaryWithWrongAlgorithm() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-17", "base64")
};

(:~ Hashing a binary with a wrong algorithm and the default format. Test will pass if the correct error is thrown. :)
declare
    %test:name("Hash binary with wrong algorithm, default format")
    %test:assertError("err:CX21: The algorithm is not supported.")
function t:hashBinaryWithWrongAlgorithmAndDefaultFormat() {
    let $input := util:binary-doc("/db/test/keystore.ks")
    return
        crypto:hash($input, "SHA-17", ())
};

(:~ Hashing an XML file with 'MD5' algorithm. :)
declare
    %test:name("'MD5' hashing for string")
    %test:assertEquals("use1oAoe8vIgnFgygz2OKw==")
function t:hashStringWithMd5() {
    crypto:hash("Short string for tests.", "MD5", "base64")
};

(:~ Hashing an XML file with 'MD5' algorithm and the default format. :)
declare
    %test:name("'MD5' hashing for string, default format")
    %test:assertEquals("use1oAoe8vIgnFgygz2OKw==")
function t:hashStringWithMd5AndDefaultFormat() {
    crypto:hash("Short string for tests.", "MD5")
};

(:~ Hashing a string by using 'SHA-1' algorithm. :)
declare
    %test:name("'SHA-1' hashing for string")
    %test:assertEquals("cV2wx17vo8eH2TaFRvCIIvJjNqU=")
function t:hashStringWithSha1() {
    crypto:hash("Short string for tests.", "SHA-1", "base64")
};

(:~ Hashing a string by using 'SHA-1' algorithm and the default format. :)
declare
    %test:name("'SHA-1' hashing for string, default format")
    %test:assertEquals("cV2wx17vo8eH2TaFRvCIIvJjNqU=")
function t:hashStringWithSha1AndDefaultFormat() {
    crypto:hash("Short string for tests.", "SHA-1")
};

(:~ Hashing a string by using 'SHA-256' algorithm. :)
declare
    %test:name("'SHA-256' hashing for string")
    %test:assertEquals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=")
function t:hashStringWithSha256() {
    crypto:hash("Short string for tests.", "SHA-256", "base64")
};

(:~ Hashing a string by using 'SHA-256' algorithm and the default format. :)
declare
    %test:name("'SHA-256' hashing for string, default format")
    %test:assertEquals("E+B0JzLRgxm2+1rB8qIZoQ2Qn+JLxwJCWORv46fKhMM=")
function t:hashStringWithSha256AndDefaultFormat() {
    crypto:hash("Short string for tests.", "SHA-256")
};

(:~ Hashing a string by using 'SHA-384' algorithm. :)
declare
    %test:assertEquals("F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La")
    %test:name("'SHA-384' hashing for string")
function t:hashStringWithSha384() {
    crypto:hash("Short string for tests.", "SHA-384", "base64")
};

(:~ Hashing a string by using 'SHA-384' algorithm and the default format. :)
declare
    %test:assertEquals("F4CFDSBHm+Bm400bOgH2q2IbIUj8XRUBWf0inx7lrN0T8IHz9scGVmJoGZ2+s1La")
    %test:name("'SHA-384' hashing for string, default format")
function t:hashStringWithSha384AndDefaultFormat() {
    crypto:hash("Short string for tests.", "SHA-384")
};

(:~ Hashing a string by using 'SHA-512' algorithm. :)
declare
    %test:assertEquals("+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdMFZ0+/JFK2g==")
    %test:name("'SHA-512' hashing for string")
function t:hashStringWithSha512() {
    crypto:hash("Short string for tests.", "SHA-512", "base64")
};

(:~ Hashing a string by using 'SHA-512' algorithm and the default format. :)
declare
    %test:name("'SHA-512' hashing for string, default format")
    %test:assertEquals("+YpeZRBrctlL1xr6plZOScp/6ArUw3GihjtKys1e3qQ6/aWLFjoOFEfuiUJA3uLIkebH1OG+rDdMFZ0+/JFK2g==")
function t:hashStringWithSha512AndDefaultFormat() {
    crypto:hash("Short string for tests.", "SHA-512")
};

(:~ Hashing an XML file with 'MD5' algorithm. :)
declare
    %test:name("'MD5' hashing for XML file")
    %test:assertEquals("xMpCOKC5I4INzFCab3WEmw==")
function t:hashXmlWithMd5() {
    let $input := $t:DOC-1
    return
        crypto:hash($input/*/*[1], "MD5", "base64")
};

(:~ Hashing an XML file with 'MD5' algorithm and the default format. :)
declare
    %test:name("'MD5' hashing for XML file, default format")
    %test:assertEquals("xMpCOKC5I4INzFCab3WEmw==")
function t:hashXmlWithMd5AndDefaultFormat() {
    let $input := $t:DOC-1
    return
        crypto:hash($input/*/*[1], "MD5")
};

(:~ HMAC for a string by using 'MD5' algorithm. :)
declare
    %test:name("'MD5' HMAC for string")
    %test:assertEquals("l4MY6Yosjo7W60VJeXB/PQ==")
function t:hmacStringWithMd5() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-MD5", "base64")
};

(:~ HMAC for a string by using 'MD5' algorithm and the default format. :)
declare
    %test:name("'MD5' HMAC for string, default format")
    %test:assertEquals("l4MY6Yosjo7W60VJeXB/PQ==")
function t:hmacStringWithMd5AndDefaultFormat() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-MD5")
};

(:~ HMAC for a string by using 'SHA-1' algorithm. :)
declare
    %test:name("'SHA-1' HMAC for string")
    %test:assertEquals("55LyDq7GFnqijauK4CQWR4AqyZk=")
function t:hmacStringWithSha1() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HmacSha1", "base64")
};

(:~ HMAC for a string by using 'SHA-1' algorithm and the default format. :)
declare
    %test:name("'SHA-1' HMAC for string, default format")
    %test:assertEquals("55LyDq7GFnqijauK4CQWR4AqyZk=")
function t:hmacStringWithSha1AndDefaultFormat() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-1")
};

(:~ HMAC for a string by using 'SHA-256' algorithm. :)
declare
    %test:name("'SHA-256' HMAC for string")
    %test:assertEquals("FfZidcLEUg4oJLIZfw6xHlPMz8KPHxo2liaBKgLfcOE=")
function t:hmacStringWithSha256() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HmacSha256", "base64")
};

(:~ HMAC for a string by using 'SHA-256' algorithm and the default format. :)
declare
    %test:name("'SHA-256' HMAC for string, default format")
    %test:assertEquals("FfZidcLEUg4oJLIZfw6xHlPMz8KPHxo2liaBKgLfcOE=")
function t:hmacStringWithSha256AndDefaultFormat() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-256")
};

(:~ HMAC for a string by using 'SHA-384' algorithm. :)
declare
    %test:name("'SHA-384' HMAC for string")
    %test:assertEquals("RRirKZTmx+cG8EXvgrRnpYFPEPYXaZBirY+LFmiUBAK61LCryDsL4clFRG5/BcBr")
function t:hmacStringWithSha384() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-384", "base64")
};

(:~ HMAC for a string by using 'SHA-384' algorithm and the default format. :)
declare
    %test:name("'SHA-384' HMAC for string, default format")
    %test:assertEquals("RRirKZTmx+cG8EXvgrRnpYFPEPYXaZBirY+LFmiUBAK61LCryDsL4clFRG5/BcBr")
function t:hmacStringWithSha384AndDefaultFormat() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-384")
};

(:~ Authenticating a REST Request as needed by S3 Amazon Web Service. :)
declare
    %test:name("'SHA-512' HMAC for string")
    %test:assertEquals("z9MtEpBXxO5bKmsXJWfKsZ4v+RduKU89Y95H2HMGQEwHGefWmewNNQ7urZVuWEU5aeRRdO7G7j0QlcLYv1pkrg==")
function t:hmacStringWithSha512() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-512", "base64")
};

(:~ Authenticating a REST Request as needed by S3 Amazon Web Service with default format. :)
declare
    %test:name("'SHA-512' HMAC for string, default format")
    %test:assertEquals("z9MtEpBXxO5bKmsXJWfKsZ4v+RduKU89Y95H2HMGQEwHGefWmewNNQ7urZVuWEU5aeRRdO7G7j0QlcLYv1pkrg==")
function t:hmacStringWithSha512AndDefaultFormat() {
    let $private-key := $t:PRIVATE_KEY_PEM
    return
        crypto:hmac("Short string for tests.", $private-key, "HMAC-SHA-512")
};

(:~ Validate an enveloped digital signature, which is generated by using the following parameters:
 : 'SHA1' canonicalization algorithm, 
 : 'DSA_SHA1' signature algorithm,
 : 'dsig' signature namespace prefix, 
 : and an X509 certificate. :)
declare
    %test:name("Validate enveloped digital signature")
    %test:assertTrue
function t:validateEnvelopedDigitalSignature() {
    let $input := $t:DOC-1
    let $certificate-details :=
        <digital-certificate>
            <keystore-type>JKS</keystore-type>
            <keystore-password>ab987c</keystore-password>
            <key-alias>eXist</key-alias>
            <private-key-password>kpi135</private-key-password>
            <keystore-uri>xmldb:///db/test/keystore.ks</keystore-uri>
        </digital-certificate>
    let $signed-doc := crypto:generate-signature($input, "inclusive", "SHA1", "DSA_SHA1", "dsig", "enveloped")
    return
        crypto:validate-signature($signed-doc)
};
