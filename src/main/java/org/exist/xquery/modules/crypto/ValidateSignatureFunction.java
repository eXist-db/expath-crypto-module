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

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BooleanValue;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.Type;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:validate-signature()} — XML digital signature validation.
 *
 * <p>Extracts the public key from the KeyInfo element in the signed document and validates
 * the signature against it.</p>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms (§8 validate-signature)</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — conforms</li>
 *   <li><b>BaseX</b> — conforms ({@code crypto:validate-signature($input-doc)})</li>
 *   <li><b>expath-crypto-module 6.x</b> — fully backward compatible</li>
 * </ul>
 */
public class ValidateSignatureFunction extends BasicFunction {

    private static final String FS_NAME = "validate-signature";

    public static final FunctionSignature[] FS_VALIDATE_SIGNATURE = functionSignatures(
            CryptoModule.qname(FS_NAME),
            """
            Validates an XML digital signature. Returns true if the signature is valid, \
            false otherwise. The public key is extracted from the KeyInfo element.""",
            returns(Type.BOOLEAN, "true if the signature is valid"),
            arities(
                    arity(
                            param("data", Type.NODE,
                                    "The signed XML document containing a Signature element.")
                    )
            )
    );

    public ValidateSignatureFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final NodeValue inputNode = (NodeValue) args[0].itemAt(0);

        try {
            final Document domDoc = SignatureUtils.nodeToDomDocument(
                    context.getBroker(), inputNode);

            // Find the Signature element
            final NodeList signatureNodes = domDoc.getElementsByTagNameNS(
                    XMLSignature.XMLNS, "Signature");
            if (signatureNodes.getLength() == 0) {
                throw new XPathException(this,
                        "No XML Signature element found in the input document.");
            }

            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            final DOMValidateContext valContext = new DOMValidateContext(
                    new KeyValueKeySelector(), signatureNodes.item(0));

            final XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            final boolean valid = signature.validate(valContext);

            return BooleanValue.valueOf(valid);

        } catch (final MarshalException | XMLSignatureException e) {
            throw new XPathException(this,
                    "Failed to validate XML signature: " + e.getMessage(), e);
        }
    }

    /**
     * KeySelector that extracts the public key from the KeyValue element in KeyInfo.
     */
    private static class KeyValueKeySelector extends KeySelector {
        @Override
        public KeySelectorResult select(final KeyInfo keyInfo, final Purpose purpose,
                final AlgorithmMethod method, final XMLCryptoContext context)
                throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("No KeyInfo in signature");
            }

            for (final Object content : keyInfo.getContent()) {
                final XMLStructure xmlStructure = (XMLStructure) content;
                if (xmlStructure instanceof final KeyValue keyValue) {
                    try {
                        final PublicKey pk = keyValue.getPublicKey();
                        return () -> pk;
                    } catch (final KeyException e) {
                        throw new KeySelectorException(e);
                    }
                }
            }
            throw new KeySelectorException("No KeyValue found in KeyInfo");
        }
    }
}
