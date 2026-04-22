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
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:decrypt()} — symmetric decryption using AES or DES.
 *
 * <p>Two arities:</p>
 * <ul>
 *   <li>{@code crypto:decrypt($data, $type, $key, $algorithm)} — expects IV prepended
 *       to ciphertext (as produced by 4-param {@code crypto:encrypt()})</li>
 *   <li>{@code crypto:decrypt($data, $type, $key, $algorithm, $iv, $provider)} — uses
 *       supplied IV; treats input as raw ciphertext (6-param, backward compat)</li>
 * </ul>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms for symmetric decryption (§6 decrypt)</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — the draft uses a {@code $parameters} map;
 *       we use positional params for backward compat</li>
 *   <li><b>BaseX</b> — 4-param arity matches BaseX exactly</li>
 *   <li><b>expath-crypto-module 6.x</b> — 6-param arity preserves backward compat.
 *       <b>Breaking change:</b> v6 passed encrypted data as dash-separated byte
 *       strings; v7 expects {@code xs:base64Binary}. Code that stored v6 ciphertext
 *       will need to re-encrypt with v7.</li>
 * </ul>
 */
public class DecryptFunction extends BasicFunction {

    private static final String FS_DECRYPT_NAME = "decrypt";

    public static final FunctionSignature[] FS_DECRYPT = functionSignatures(
            CryptoModule.qname(FS_DECRYPT_NAME),
            """
            Decrypts the given data using symmetric decryption (AES or DES). \
            The input must be the result of crypto:encrypt() with the IV prepended.""",
            returns(Type.STRING, "the decrypted plaintext"),
            arities(
                    arity(
                            param("data", Type.BASE64_BINARY,
                                    "The encrypted data as xs:base64Binary (IV + ciphertext)."),
                            param("type", Type.STRING, "The encryption type: 'symmetric'."),
                            param("key", Type.STRING,
                                    "The secret key (must match the key used for encryption)."),
                            param("algorithm", Type.STRING,
                                    "The encryption algorithm: 'AES' or 'DES'.")
                    ),
                    arity(
                            param("data", Type.BASE64_BINARY,
                                    "The encrypted data as xs:base64Binary."),
                            param("type", Type.STRING, "The encryption type: 'symmetric'."),
                            param("key", Type.STRING,
                                    "The secret key (must match the key used for encryption)."),
                            param("algorithm", Type.STRING,
                                    "The encryption algorithm: 'AES' or 'DES'."),
                            param("iv", Type.STRING,
                                    "The initialization vector used during encryption."),
                            param("provider", Type.STRING,
                                    "The cryptographic provider (ignored if empty).")
                    )
            )
    );

    public DecryptFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final BinaryValue binaryValue = (BinaryValue) args[0].itemAt(0);
        final byte[] inputBytes;
        try (final InputStream is = binaryValue.getInputStream()) {
            inputBytes = is.readAllBytes();
        } catch (final IOException e) {
            throw new XPathException(this, "Failed to read binary data: " + e.getMessage(), e);
        }
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
            final int blockSize = cipher.getBlockSize();

            final byte[] iv;
            final byte[] ciphertext;

            if (!ivParam.isEmpty()) {
                // External IV: ciphertext is the entire input (no prepended IV)
                iv = ivParam.getBytes(StandardCharsets.UTF_8);
                final byte[] sized = new byte[blockSize];
                System.arraycopy(iv, 0, sized, 0, Math.min(iv.length, sized.length));
                ciphertext = inputBytes;
                final SecretKeySpec keySpec = new SecretKeySpec(
                        key.getBytes(StandardCharsets.UTF_8), algorithm);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(sized));
                final byte[] decrypted = cipher.doFinal(ciphertext);
                return new StringValue(this, new String(decrypted, StandardCharsets.UTF_8));
            }

            // Auto IV: extract from beginning of input
            if (inputBytes.length < blockSize) {
                throw new XPathException(this,
                        "Encrypted data is too short — must contain at least the IV (" +
                                blockSize + " bytes).");
            }

            iv = Arrays.copyOfRange(inputBytes, 0, blockSize);
            ciphertext = Arrays.copyOfRange(inputBytes, blockSize, inputBytes.length);

            final SecretKeySpec keySpec = new SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8), algorithm);
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            final byte[] decrypted = cipher.doFinal(ciphertext);

            return new StringValue(this, new String(decrypted, StandardCharsets.UTF_8));
        } catch (final GeneralSecurityException e) {
            throw new XPathException(this, "Decryption failed: " + e.getMessage(), e);
        }
    }
}
