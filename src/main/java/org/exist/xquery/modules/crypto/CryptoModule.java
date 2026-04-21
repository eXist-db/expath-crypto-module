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

import org.exist.dom.QName;
import org.exist.xquery.AbstractInternalModule;
import org.exist.xquery.FunctionDef;

import java.util.List;
import java.util.Map;

import static org.exist.xquery.FunctionDSL.functionDefs;

/**
 * XQuery function module implementing the EXPath Cryptographic Module.
 *
 * <p>Provides HMAC, symmetric encryption/decryption, and XML digital signature
 * functions using Java's built-in JCE (Java Cryptography Extension). No external
 * cryptographic library dependencies.</p>
 *
 * <p>Version 7.0 is a drop-in replacement for expath-crypto-module 6.x.
 * All function signatures are backward compatible. Function signatures also
 * match BaseX's crypto module for cross-engine portability.</p>
 *
 * @see <a href="https://expath.org/spec/crypto">EXPath Cryptographic Module 1.0</a>
 * @see <a href="https://expath.org/spec/crypto/editor">EXPath Cryptographic Module Editor's Draft</a>
 * @see <a href="https://docs.basex.org/main/Cryptographic_Functions">BaseX Cryptographic Functions</a>
 */
public class CryptoModule extends AbstractInternalModule {

    public static final String NAMESPACE_URI = "http://expath.org/ns/crypto";

    public static final String PREFIX = "crypto";

    public static final String RELEASE = "1.0.0";

    // Functions MUST be sorted alphabetically by local name for binary search (ordered=true)
    public static final FunctionDef[] functions = functionDefs(
            functionDefs(DecryptFunction.class,
                    DecryptFunction.FS_DECRYPT),
            functionDefs(EncryptFunction.class,
                    EncryptFunction.FS_ENCRYPT),
            functionDefs(GenerateSignatureFunction.class,
                    GenerateSignatureFunction.FS_GENERATE_SIGNATURE),
            functionDefs(HashFunction.class,
                    HashFunction.FS_HASH),
            functionDefs(HmacFunction.class,
                    HmacFunction.FS_HMAC),
            // TODO: list-algorithms, list-providers, list-services (2018 CG spec)
            // Currently disabled due to a binary search issue in eXist's ordered
            // module registry when mixing zero-param and multi-param arities.
            // See ListProvidersFunction.java for the implementation.
            functionDefs(ValidateSignatureFunction.class,
                    ValidateSignatureFunction.FS_VALIDATE_SIGNATURE)
    );

    public CryptoModule(final Map<String, List<?>> parameters) {
        super(functions, parameters, true);
    }

    @Override
    public String getNamespaceURI() {
        return NAMESPACE_URI;
    }

    @Override
    public String getDefaultPrefix() {
        return PREFIX;
    }

    @Override
    public String getDescription() {
        return "EXPath Cryptographic Module: HMAC, encryption/decryption, and XML digital signatures";
    }

    @Override
    public String getReleaseVersion() {
        return RELEASE;
    }

    static QName qname(final String localPart) {
        return new QName(localPart, NAMESPACE_URI, PREFIX);
    }
}
