/*
 * eXist-db Open Source Native XML Database
 * Copyright (C) 2001 The eXist-db Authors
 *
 * info@exist-db.org
 * http://www.exist-db.org
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.exist.xquery.modules.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.Item;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:hmac()} — keyed-hash message authentication code.
 *
 * <p>Two arities:</p>
 * <ul>
 *   <li>{@code crypto:hmac($data, $key, $algorithm)} — Base64 output (default)</li>
 *   <li>{@code crypto:hmac($data, $key, $algorithm, $encoding)} — hex or base64</li>
 * </ul>
 *
 * <p>{@code $data} and {@code $key} accept {@code xs:string}, {@code xs:base64Binary},
 * and {@code xs:hexBinary}. Supported algorithms: MD5, SHA1, SHA256, SHA384, SHA512.
 * Algorithm names accept hyphenated ({@code SHA-256}), bare ({@code SHA256}), and
 * prefixed ({@code HMAC-SHA-256}) forms.</p>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms (§3 hmac)</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — conforms; spec adds {@code xs:byte*}
 *       for data/key which we accept as binary</li>
 *   <li><b>BaseX</b> — conforms; BaseX uses lowercase algorithm names ({@code md5},
 *       {@code sha256}) which we normalize correctly</li>
 *   <li><b>expath-crypto-module 6.x</b> — fully backward compatible; v6 accepted
 *       string-only for data/key, v7 additionally accepts binary input</li>
 * </ul>
 */
public class HmacFunction extends BasicFunction {

    private static final Set<String> SUPPORTED_ALGORITHMS =
            Set.of("MD5", "SHA1", "SHA256", "SHA384", "SHA512",
                    "HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512");

    private static final String FS_HMAC_NAME = "hmac";

    public static final FunctionSignature[] FS_HMAC = functionSignatures(
            CryptoModule.qname(FS_HMAC_NAME),
            "Calculates the HMAC (keyed-hash message authentication code) of the given data " +
                    "using the specified key and algorithm.",
            returns(Type.STRING, "the HMAC value"),
            arities(
                    arity(
                            param("data", Type.ANY_ATOMIC_TYPE,
                                    "The data to authenticate (xs:string, xs:base64Binary, or xs:hexBinary)."),
                            param("key", Type.ANY_ATOMIC_TYPE,
                                    "The secret key (xs:string, xs:base64Binary, or xs:hexBinary)."),
                            param("algorithm", Type.STRING,
                                    "The hash algorithm: MD5, SHA1, SHA256, SHA384, or SHA512.")
                    ),
                    arity(
                            param("data", Type.ANY_ATOMIC_TYPE,
                                    "The data to authenticate (xs:string, xs:base64Binary, or xs:hexBinary)."),
                            param("key", Type.ANY_ATOMIC_TYPE,
                                    "The secret key (xs:string, xs:base64Binary, or xs:hexBinary)."),
                            param("algorithm", Type.STRING,
                                    "The hash algorithm: MD5, SHA1, SHA256, SHA384, or SHA512."),
                            param("encoding", Type.STRING,
                                    "The output encoding: 'base64' (default) or 'hex'.")
                    )
            )
    );

    public HmacFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final byte[] dataBytes = toBytes(args[0]);
        final byte[] keyBytes = toBytes(args[1]);
        final String algorithm = args[2].getStringValue();
        final String encoding = getArgumentCount() == 4 ? args[3].getStringValue() : "base64";

        final String jceAlgorithm = toJceAlgorithm(algorithm);

        try {
            final Mac mac = Mac.getInstance(jceAlgorithm);
            final SecretKeySpec keySpec = new SecretKeySpec(keyBytes, jceAlgorithm);
            mac.init(keySpec);
            final byte[] result = mac.doFinal(dataBytes);

            final String encoded;
            if ("hex".equalsIgnoreCase(encoding)) {
                encoded = HexFormat.of().formatHex(result);
            } else if ("base64".equalsIgnoreCase(encoding)) {
                encoded = Base64.getEncoder().encodeToString(result);
            } else {
                throw new XPathException(this,
                        "Unsupported encoding: " + encoding + ". Use 'base64' or 'hex'.");
            }

            return new StringValue(this, encoded);
        } catch (final NoSuchAlgorithmException e) {
            throw new XPathException(this, "Unsupported HMAC algorithm: " + algorithm, e);
        } catch (final InvalidKeyException e) {
            throw new XPathException(this, "Invalid key for HMAC: " + e.getMessage(), e);
        }
    }

    /**
     * Convert an item to bytes. Handles xs:string, xs:base64Binary, and xs:hexBinary.
     */
    private byte[] toBytes(final Sequence seq) throws XPathException {
        final Item item = seq.itemAt(0);
        if (item instanceof BinaryValue) {
            try (final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
                ((BinaryValue) item).streamBinaryTo(baos);
                return baos.toByteArray();
            } catch (final java.io.IOException e) {
                throw new XPathException(this, "Error reading binary value: " + e.getMessage(), e);
            }
        }
        return item.getStringValue().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Normalizes the user-supplied algorithm name to a JCE algorithm identifier.
     * Accepts both bare names (SHA256) and prefixed names (HMACSHA256).
     */
    private String toJceAlgorithm(final String algorithm) throws XPathException {
        final String upper = algorithm.toUpperCase().replace("-", "");

        if (!SUPPORTED_ALGORITHMS.contains(upper)) {
            throw new XPathException(this,
                    "Unsupported HMAC algorithm: " + algorithm +
                            ". Supported: MD5, SHA1, SHA256, SHA384, SHA512.");
        }

        // Normalize to JCE format: "HmacSHA256", "HmacMD5", etc.
        final String bare = upper.startsWith("HMAC") ? upper.substring(4) : upper;
        return "Hmac" + bare;
    }
}
