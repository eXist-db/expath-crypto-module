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

import org.exist.xquery.Expression;
import org.exist.xquery.XPathException;

/**
 * Shared validation utilities for crypto functions.
 */
final class CryptoUtils {

    private CryptoUtils() {
        // utility class
    }

    /**
     * Validates that the algorithm is supported and the key length is correct.
     *
     * @param expr the calling expression (for error reporting)
     * @param algorithm the algorithm name (AES or DES)
     * @param key the secret key string
     * @throws XPathException if validation fails
     */
    static void validateAlgorithmAndKey(final Expression expr, final String algorithm,
            final String key) throws XPathException {
        final int keyLength = key.getBytes(StandardCharsets.UTF_8).length;

        switch (algorithm) {
            case "AES":
                if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
                    throw new XPathException(expr,
                            "AES key must be 16, 24, or 32 bytes, got " + keyLength + " bytes.");
                }
                break;
            case "DES":
                if (keyLength != 8) {
                    throw new XPathException(expr,
                            "DES key must be 8 bytes, got " + keyLength + " bytes.");
                }
                break;
            default:
                throw new XPathException(expr,
                        "Unsupported encryption algorithm: " + algorithm +
                                ". Supported: AES, DES.");
        }
    }
}
