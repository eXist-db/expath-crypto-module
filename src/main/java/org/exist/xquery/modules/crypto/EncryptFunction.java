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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.Base64BinaryValueType;
import org.exist.xquery.value.BinaryValueFromBinaryString;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.Type;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:encrypt()} — symmetric encryption using AES or DES.
 *
 * <p>Two arities:</p>
 * <ul>
 *   <li>{@code crypto:encrypt($data, $type, $key, $algorithm)} — auto-generates IV,
 *       prepends it to ciphertext (4-param)</li>
 *   <li>{@code crypto:encrypt($data, $type, $key, $algorithm, $iv, $provider)} — uses
 *       supplied IV and provider; returns ciphertext only (6-param, backward compat)</li>
 * </ul>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms for symmetric encryption (§5 encrypt)</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — the draft uses a {@code $parameters} map
 *       instead of positional params; we use positional params for backward compat</li>
 *   <li><b>BaseX</b> — 4-param arity matches BaseX exactly
 *       ({@code crypto:encrypt($data, $type, $key, $algorithm)})</li>
 *   <li><b>expath-crypto-module 6.x</b> — 6-param arity preserves full backward
 *       compatibility with v6's {@code $iv} and {@code $provider} parameters.
 *       <b>Breaking change:</b> v6 returned dash-separated byte strings
 *       ({@code "51-143-171-..."}); v7 returns {@code xs:base64Binary}.
 *       Decrypt is adapted to accept both formats.</li>
 * </ul>
 */
public class EncryptFunction extends BasicFunction {

    private static final String FS_ENCRYPT_NAME = "encrypt";

    public static final FunctionSignature[] FS_ENCRYPT = functionSignatures(
            CryptoModule.qname(FS_ENCRYPT_NAME),
            "Encrypts the given data using symmetric encryption (AES or DES). " +
                    "The initialization vector is prepended to the ciphertext in the result.",
            returns(Type.BASE64_BINARY, "the encrypted data as xs:base64Binary (IV + ciphertext)"),
            arities(
                    arity(
                            param("data", Type.STRING, "The plaintext data to encrypt."),
                            param("type", Type.STRING, "The encryption type: 'symmetric'."),
                            param("key", Type.STRING,
                                    "The secret key (16 bytes for AES, 8 bytes for DES)."),
                            param("algorithm", Type.STRING,
                                    "The encryption algorithm: 'AES' or 'DES'.")
                    ),
                    arity(
                            param("data", Type.STRING, "The plaintext data to encrypt."),
                            param("type", Type.STRING, "The encryption type: 'symmetric'."),
                            param("key", Type.STRING,
                                    "The secret key (16 bytes for AES, 8 bytes for DES)."),
                            param("algorithm", Type.STRING,
                                    "The encryption algorithm: 'AES' or 'DES'."),
                            param("iv", Type.STRING,
                                    "The initialization vector (for backward compat; ignored if empty)."),
                            param("provider", Type.STRING,
                                    "The cryptographic provider (for backward compat; ignored if empty).")
                    )
            )
    );

    public EncryptFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final String data = args[0].getStringValue();
        final String type = args[1].getStringValue();
        final String key = args[2].getStringValue();
        final String algorithm = args[3].getStringValue().toUpperCase();

        if (!"symmetric".equalsIgnoreCase(type)) {
            throw new XPathException(this,
                    "Unsupported encryption type: " + type + ". Only 'symmetric' is supported.");
        }

        CryptoUtils.validateAlgorithmAndKey(this, algorithm, key);

        // 6-param arity: optional IV and provider
        final String ivParam = getArgumentCount() >= 5 ? args[4].getStringValue() : "";
        final String provider = getArgumentCount() >= 6 ? args[5].getStringValue() : "";

        try {
            final String transformation = algorithm + "/CBC/PKCS5Padding";
            final Cipher cipher = provider.isEmpty()
                    ? Cipher.getInstance(transformation)
                    : Cipher.getInstance(transformation, provider);
            final SecretKeySpec keySpec = new SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8), algorithm);

            // Use provided IV or generate random one
            final byte[] iv;
            if (!ivParam.isEmpty()) {
                iv = ivParam.getBytes(StandardCharsets.UTF_8);
                // Pad or trim to block size
                final byte[] sized = new byte[cipher.getBlockSize()];
                System.arraycopy(iv, 0, sized, 0, Math.min(iv.length, sized.length));
                final IvParameterSpec ivSpec = new IvParameterSpec(sized);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                final byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
                // When IV is provided externally, return just ciphertext (old module compat)
                final String base64 = java.util.Base64.getEncoder().encodeToString(encrypted);
                return new BinaryValueFromBinaryString(this, new Base64BinaryValueType(), base64);
            }

            iv = new byte[cipher.getBlockSize()];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            final byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            // Prepend IV to ciphertext
            final byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

            final String base64 = java.util.Base64.getEncoder().encodeToString(result);
            return new BinaryValueFromBinaryString(this, new Base64BinaryValueType(), base64);
        } catch (final GeneralSecurityException e) {
            throw new XPathException(this, "Encryption failed: " + e.getMessage(), e);
        }
    }
}
