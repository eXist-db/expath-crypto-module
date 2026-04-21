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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.Item;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:hash()} — cryptographic hashing.
 *
 * <p>Two arities:</p>
 * <ul>
 *   <li>{@code crypto:hash($data, $algorithm)} — Base64 output (default)</li>
 *   <li>{@code crypto:hash($data, $algorithm, $encoding)} — hex or base64</li>
 * </ul>
 *
 * <p>Accepts string, binary, and node input. Nodes are serialized to their
 * string value before hashing.</p>
 *
 * <p>For new code, prefer {@code fn:hash()} (XQuery 4.0) or {@code util:hash()}.</p>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms (§2 hash)</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — conforms (§2 hash)</li>
 *   <li><b>BaseX</b> — BaseX does not include {@code crypto:hash}; it uses {@code fn:hash} instead</li>
 *   <li><b>expath-crypto-module 6.x</b> — fully backward compatible</li>
 * </ul>
 * {@code crypto:hash} is provided for backward compatibility with the EXPath
 * Cryptographic Module specification and cross-engine portability (BaseX also
 * implements it).</p>
 *
 * <p>Supported algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512.</p>
 */
public class HashFunction extends BasicFunction {

    private static final String FS_HASH_NAME = "hash";

    public static final FunctionSignature[] FS_HASH = functionSignatures(
            CryptoModule.qname(FS_HASH_NAME),
            "Computes the hash of the given data using the specified algorithm. " +
                    "For new code, prefer fn:hash() (XQuery 4.0) or util:hash(). " +
                    "crypto:hash is provided for backward compatibility and cross-engine portability.",
            returns(Type.STRING, "the hash value as a base64 or hex string"),
            arities(
                    arity(
                            param("data", Type.ITEM, "The data to hash " +
                                    "(xs:string, xs:base64Binary, xs:hexBinary, or node)."),
                            param("algorithm", Type.STRING,
                                    "The hash algorithm: MD5, SHA-1, SHA-256, SHA-384, or SHA-512.")
                    ),
                    arity(
                            param("data", Type.ITEM, "The data to hash " +
                                    "(xs:string, xs:base64Binary, xs:hexBinary, or node)."),
                            param("algorithm", Type.STRING,
                                    "The hash algorithm: MD5, SHA-1, SHA-256, SHA-384, or SHA-512."),
                            param("encoding", Type.STRING,
                                    "The output encoding: 'base64' (default) or 'hex'.")
                    )
            )
    );

    public HashFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        if (args[0].isEmpty()) {
            return Sequence.EMPTY_SEQUENCE;
        }

        final Item data = args[0].itemAt(0);
        final String algorithm = args[1].getStringValue();
        final String encoding = getArgumentCount() == 3 ? args[2].getStringValue() : "base64";

        final String jceAlgorithm = toJceAlgorithm(algorithm);

        try {
            final MessageDigest digest = MessageDigest.getInstance(jceAlgorithm);
            final byte[] input = itemToBytes(data);
            final byte[] hash = digest.digest(input);

            final String encoded;
            if ("hex".equalsIgnoreCase(encoding)) {
                encoded = HexFormat.of().formatHex(hash);
            } else if ("base64".equalsIgnoreCase(encoding)) {
                encoded = Base64.getEncoder().encodeToString(hash);
            } else {
                throw new XPathException(this,
                        "Unsupported encoding: " + encoding + ". Use 'base64' or 'hex'.");
            }

            return new StringValue(this, encoded);
        } catch (final NoSuchAlgorithmException e) {
            throw new XPathException(this, "Unsupported hash algorithm: " + algorithm, e);
        }
    }

    /**
     * Converts an XQuery item to a byte array for hashing.
     */
    private byte[] itemToBytes(final Item item) throws XPathException {
        return switch (item.getType()) {
            case Type.BASE64_BINARY, Type.HEX_BINARY -> {
                try (final InputStream is = ((BinaryValue) item).getInputStream()) {
                    yield is.readAllBytes();
                } catch (final IOException e) {
                    throw new XPathException(this, "Failed to read binary data: " + e.getMessage(), e);
                }
            }
            default -> item.getStringValue().getBytes(StandardCharsets.UTF_8);
        };
    }

    /**
     * Normalizes the user-supplied algorithm name to a JCE MessageDigest identifier.
     * Accepts both hyphenated (SHA-256) and bare (SHA256) forms.
     */
    private String toJceAlgorithm(final String algorithm) throws XPathException {
        return switch (algorithm.toUpperCase().replace("-", "")) {
            case "MD5" -> "MD5";
            case "SHA1" -> "SHA-1";
            case "SHA256" -> "SHA-256";
            case "SHA384" -> "SHA-384";
            case "SHA512" -> "SHA-512";
            default -> throw new XPathException(this,
                    "Unsupported hash algorithm: " + algorithm +
                            ". Supported: MD5, SHA-1, SHA-256, SHA-384, SHA-512.");
        };
    }
}
