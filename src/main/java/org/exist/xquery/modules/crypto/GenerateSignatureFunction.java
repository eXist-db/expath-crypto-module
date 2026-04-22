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

import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.functions.map.AbstractMapType;
import org.exist.xquery.value.AtomicValue;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import static org.exist.xquery.FunctionDSL.*;

/**
 * Implements {@code crypto:generate-signature()} — XML digital signature generation.
 *
 * <p>Five arities:</p>
 * <ul>
 *   <li><b>6-param:</b> {@code ($data, $canonicalization, $digest, $signature,
 *       $prefix, $type)} — generated key pair</li>
 *   <li><b>7-param:</b> + {@code $xpath-expression} — sign a subset selected by XPath</li>
 *   <li><b>8-param:</b> + {@code $digital-certificate} — sign with a keystore certificate</li>
 *   <li><b>3-param:</b> {@code ($data, $private-key, $signature-algorithm)} — simplified
 *       RSA signing with a base64-encoded PKCS#8 private key</li>
 *   <li><b>2-param:</b> {@code ($data, $parameters as map(*))} — map-based configuration
 *       per the 2018 CG spec and editor's draft</li>
 * </ul>
 *
 * <h3>Conformance</h3>
 * <ul>
 *   <li><b>EXPath Crypto 1.0</b> — conforms (§7 generate-signature). The spec defines
 *       multiple arities with positional params matching our 6/7/8-param forms.</li>
 *   <li><b>EXPath Crypto 2018 CG</b> — conforms. The 2-param map-based arity implements
 *       the consolidated {@code $parameters as map(xs:string, item()+)} signature.
 *       Algorithm names {@code DSAwithSHA1}/{@code RSAwithSHA1} accepted per this spec.
 *       Canonicalization 1.1 options ({@code inclusive-1.1},
 *       {@code inclusive-with-comments-1.1}) added per this spec.</li>
 *   <li><b>EXPath Crypto Editor's Draft</b> — the draft also uses a {@code $parameters}
 *       map, matching the 2018 CG spec.</li>
 *   <li><b>BaseX</b> — BaseX uses 6 required + 2 optional params (matching our 6/7/8-param
 *       arities). Certificate element format is compatible.</li>
 *   <li><b>expath-crypto-module 6.x</b> — all 4 positional arities from v6 preserved.
 *       The 7-param cert-only arity was commented out in v6 and remains absent here.
 *       <b>Note:</b> DSA_SHA1 signatures are forbidden by Java 17+ secure validation.
 *       Use RSA_SHA256 instead.</li>
 * </ul>
 */
public class GenerateSignatureFunction extends BasicFunction {

    private static final String FS_NAME = "generate-signature";

    public static final FunctionSignature[] FS_GENERATE_SIGNATURE = functionSignatures(
            CryptoModule.qname(FS_NAME),
            """
            Generates an XML digital signature for the given node. \
            Uses a generated key pair (RSA or DSA) and returns the signed document.""",
            returns(Type.NODE, "the signed XML document"),
            arities(
                    // 6-param: generated key pair
                    arity(
                            param("data", Type.NODE, "The XML node to sign."),
                            param("canonicalization", Type.STRING,
                                    """
                                    Canonicalization: 'inclusive', 'inclusive-with-comments', \
                                    'exclusive', or 'exclusive-with-comments'."""),
                            param("digest", Type.STRING,
                                    "Digest algorithm: 'SHA1', 'SHA256', or 'SHA512'."),
                            param("signature", Type.STRING,
                                    "Signature algorithm: 'RSA_SHA1', 'DSA_SHA1', or 'RSA_SHA256'."),
                            param("signature-namespace-prefix", Type.STRING,
                                    "The namespace prefix for the signature element (e.g. 'dsig')."),
                            param("signature-type", Type.STRING,
                                    "The signature type: 'enveloped' or 'enveloping'.")
                    ),
                    // 7-param: + XPath expression for selective signing
                    arity(
                            param("data", Type.NODE, "The XML node to sign."),
                            param("canonicalization", Type.STRING, "Canonicalization algorithm."),
                            param("digest", Type.STRING, "Digest algorithm."),
                            param("signature", Type.STRING, "Signature algorithm."),
                            param("signature-namespace-prefix", Type.STRING, "Namespace prefix."),
                            param("signature-type", Type.STRING, "Signature type."),
                            param("xpath-expression", Type.ANY_TYPE,
                                    "XPath expression selecting the subset to sign.")
                    ),
                    // 8-param: + XPath + digital certificate
                    arity(
                            param("data", Type.NODE, "The XML node to sign."),
                            param("canonicalization", Type.STRING, "Canonicalization algorithm."),
                            param("digest", Type.STRING, "Digest algorithm."),
                            param("signature", Type.STRING, "Signature algorithm."),
                            param("signature-namespace-prefix", Type.STRING, "Namespace prefix."),
                            param("signature-type", Type.STRING, "Signature type."),
                            param("xpath-expression", Type.ANY_TYPE,
                                    "XPath expression selecting the subset to sign."),
                            param("digital-certificate", Type.ANY_TYPE,
                                    """
                                    Certificate details element with keystore-type, keystore-password, \
                                    key-alias, private-key-password, keystore-uri.""")
                    ),
                    // 3-param: simplified RSA signing with private key
                    arity(
                            param("data", Type.NODE, "The XML node to sign."),
                            param("private-key", Type.STRING,
                                    "Base64-encoded PKCS#8 private key."),
                            param("signature-algorithm", Type.STRING,
                                    "Signature algorithm: 'RSA_SHA1', 'DSA_SHA1', or 'RSA_SHA256'.")
                    ),
                    // 2-param: map-based (2018 CG spec / editor's draft)
                    arity(
                            param("data", Type.NODE, "The XML node to sign."),
                            param("parameters", Type.MAP_ITEM,
                                    """
                                    Map with keys: canonicalization-algorithm, digest-algorithm, \
                                    signature-algorithm, signature-namespace-prefix, signature-type, \
                                    key (optional base64 private key).""")
                    )
            )
    );

    public GenerateSignatureFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        // 2-param arity: map-based (2018 CG spec / editor's draft)
        if (getArgumentCount() == 2 && args[1].itemAt(0) instanceof AbstractMapType) {
            return evalMapBased(args);
        }

        // 3-param arity: simplified private key signing
        if (getArgumentCount() == 3) {
            return evalSimplifiedSigning(args);
        }

        return evalPositional(args);
    }

    /**
     * Main positional-parameter implementation for 6/7/8-param arities.
     */
    private Sequence evalPositional(final Sequence[] args) throws XPathException {
        final NodeValue inputNode = (NodeValue) args[0].itemAt(0);
        final String canonicalization = args[1].getStringValue();
        final String digest = args[2].getStringValue();
        final String signatureAlg = args[3].getStringValue();
        final String sigPrefix = args[4].getStringValue();
        final String signatureType = args[5].getStringValue();

        // Optional xpath expression (7-param and 8-param arities)
        final String xpathExpr = args.length >= 7 && !args[6].isEmpty()
                ? args[6].getStringValue() : null;

        // Optional digital certificate (8-param arity)
        final Node certNode = args.length >= 8 && !args[7].isEmpty()
                ? ((NodeValue) args[7].itemAt(0)).getNode() : null;

        if (!"enveloped".equalsIgnoreCase(signatureType) && !"enveloping".equalsIgnoreCase(signatureType)) {
            throw new XPathException(this,
                    "Unsupported signature type: " + signatureType +
                            ". Use 'enveloped' or 'enveloping'.");
        }

        try {
            // Convert eXist node to DOM Document
            final Document domDoc = SignatureUtils.nodeToDomDocument(
                    context.getBroker(), inputNode);

            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Build the reference
            final String digestMethodUri = resolveDigestMethod(digest);
            final List<Transform> transforms = new ArrayList<>();
            if ("enveloped".equalsIgnoreCase(signatureType)) {
                transforms.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            }
            transforms.add(fac.newTransform(resolveCanonicalization(canonicalization),
                    (TransformParameterSpec) null));

            final String refUri = xpathExpr != null ? "#xpointer(" + xpathExpr + ")" : "";
            final Reference ref = fac.newReference(refUri,
                    fac.newDigestMethod(digestMethodUri, null),
                    transforms, null, null);

            // Build signed info
            final String c14nMethodUri = resolveCanonicalization(canonicalization);
            final String sigMethodUri = resolveSignatureMethod(signatureAlg);

            final SignedInfo signedInfo = fac.newSignedInfo(
                    fac.newCanonicalizationMethod(c14nMethodUri, (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(sigMethodUri, null),
                    Collections.singletonList(ref));

            // Get signing key — from certificate or generate
            final PrivateKey privateKey;
            final KeyInfo keyInfo;

            if (certNode != null) {
                // Load from keystore
                final var certInfo = parseCertificateElement(certNode);
                final KeyStore ks = KeyStore.getInstance(certInfo.keystoreType);
                try (final FileInputStream fis = new FileInputStream(certInfo.keystoreUri)) {
                    ks.load(fis, certInfo.keystorePassword.toCharArray());
                }
                privateKey = (PrivateKey) ks.getKey(
                        certInfo.keyAlias, certInfo.privateKeyPassword.toCharArray());
                final X509Certificate cert = (X509Certificate) ks.getCertificate(certInfo.keyAlias);
                final KeyInfoFactory kif = fac.getKeyInfoFactory();
                keyInfo = kif.newKeyInfo(Collections.singletonList(
                        kif.newX509Data(Collections.singletonList(cert))));
            } else {
                // Generate key pair
                final String keyAlgorithm = signatureAlg.toUpperCase().startsWith("DSA") ? "DSA" : "RSA";
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
                kpg.initialize(keyAlgorithm.equals("DSA") ? 1024 : 2048);
                final KeyPair kp = kpg.generateKeyPair();
                privateKey = kp.getPrivate();
                final KeyInfoFactory kif = fac.getKeyInfoFactory();
                final KeyValue keyValue = kif.newKeyValue(kp.getPublic());
                keyInfo = kif.newKeyInfo(Collections.singletonList(keyValue));
            }

            // Sign
            final DOMSignContext dsc = new DOMSignContext(
                    privateKey, domDoc.getDocumentElement());
            if (sigPrefix != null && !sigPrefix.isEmpty()) {
                dsc.setDefaultNamespacePrefix(sigPrefix);
            }

            final XMLSignature xmlSignature = fac.newXMLSignature(signedInfo, keyInfo);
            xmlSignature.sign(dsc);

            // Convert back to eXist in-memory node
            return SignatureUtils.domToMemTree(context, domDoc);

        } catch (final Exception e) {
            throw new XPathException(this,
                    "Failed to generate XML signature: " + e.getMessage(), e);
        }
    }

    /**
     * 2-param map-based signing per 2018 CG spec / editor's draft.
     *
     * <h3>Conformance</h3>
     * <ul>
     *   <li><b>EXPath Crypto 2018 CG</b> — conforms (§ generate-signature with $parameters map)</li>
     *   <li><b>EXPath Crypto Editor's Draft</b> — conforms</li>
     * </ul>
     */
    private Sequence evalMapBased(final Sequence[] args) throws XPathException {
        final NodeValue inputNode = (NodeValue) args[0].itemAt(0);
        final AbstractMapType params = (AbstractMapType) args[1].itemAt(0);

        final String canonicalization = getMapString(params, "canonicalization-algorithm", "inclusive-with-comments");
        final String digest = getMapString(params, "digest-algorithm", "SHA256");
        final String signatureAlg = getMapString(params, "signature-algorithm", "RSA_SHA256");
        final String sigPrefix = getMapString(params, "signature-namespace-prefix", "dsig");
        final String signatureType = getMapString(params, "signature-type", "enveloped");
        final String privateKeyBase64 = getMapString(params, "key", null);

        // Delegate to the positional implementation by constructing the args array
        if (privateKeyBase64 != null && !privateKeyBase64.isEmpty()) {
            // Has a private key — use 3-param simplified path
            return evalSimplifiedSigning(new Sequence[] {
                    args[0],
                    new StringValue(this, privateKeyBase64),
                    new StringValue(this, signatureAlg)
            });
        }

        // No key — build positional args and delegate to the main 6-param logic
        // (can't recurse via eval() because getArgumentCount() would still be 2)
        final Sequence[] sixArgs = new Sequence[] {
                args[0],
                new StringValue(this, canonicalization),
                new StringValue(this, digest),
                new StringValue(this, signatureAlg),
                new StringValue(this, sigPrefix),
                new StringValue(this, signatureType)
        };
        return evalPositional(sixArgs);
    }

    private String getMapString(final AbstractMapType map, final String key,
                                 final String defaultValue) throws XPathException {
        final Sequence val = map.get(new StringValue(this, key));
        if (val == null || val.isEmpty()) {
            return defaultValue;
        }
        return val.getStringValue();
    }

    /**
     * 3-param simplified signing: ($data, $private-key, $signature-algorithm).
     * Signs using a base64-encoded PKCS#8 private key with default settings.
     */
    private Sequence evalSimplifiedSigning(final Sequence[] args) throws XPathException {
        final NodeValue inputNode = (NodeValue) args[0].itemAt(0);
        final String privateKeyBase64 = args[1].getStringValue();
        final String signatureAlg = args[2].getStringValue();

        try {
            final Document domDoc = SignatureUtils.nodeToDomDocument(
                    context.getBroker(), inputNode);
            final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            final String keyAlgorithm = signatureAlg.toUpperCase().startsWith("DSA") ? "DSA" : "RSA";
            final byte[] keyBytes = java.util.Base64.getDecoder().decode(privateKeyBase64);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            final PrivateKey privateKey = KeyFactory.getInstance(keyAlgorithm).generatePrivate(keySpec);

            final Reference ref = fac.newReference("",
                    fac.newDigestMethod(DigestMethod.SHA256, null),
                    Collections.singletonList(
                            fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null, null);

            final String sigMethodUri = resolveSignatureMethod(signatureAlg);
            final SignedInfo signedInfo = fac.newSignedInfo(
                    fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                            (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(sigMethodUri, null),
                    Collections.singletonList(ref));

            final DOMSignContext dsc = new DOMSignContext(
                    privateKey, domDoc.getDocumentElement());

            final XMLSignature xmlSignature = fac.newXMLSignature(signedInfo, null);
            xmlSignature.sign(dsc);

            return SignatureUtils.domToMemTree(context, domDoc);
        } catch (final Exception e) {
            throw new XPathException(this,
                    "Failed to generate XML signature: " + e.getMessage(), e);
        }
    }

    /**
     * Parse a digital-certificate element with keystore details.
     */
    private CertificateInfo parseCertificateElement(final Node certNode) throws XPathException {
        final CertificateInfo info = new CertificateInfo();
        Node child = certNode.getFirstChild();
        while (child != null) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                final String name = child.getLocalName() != null ? child.getLocalName() : child.getNodeName();
                final String value = child.getTextContent().trim();
                switch (name) {
                    case "keystore-type" -> info.keystoreType = value;
                    case "keystore-password" -> info.keystorePassword = value;
                    case "key-alias" -> info.keyAlias = value;
                    case "private-key-password" -> info.privateKeyPassword = value;
                    case "keystore-uri" -> info.keystoreUri = value;
                }
            }
            child = child.getNextSibling();
        }
        if (info.keystoreUri == null || info.keyAlias == null) {
            throw new XPathException(this,
                    "digital-certificate must contain at least keystore-uri and key-alias");
        }
        return info;
    }

    private static class CertificateInfo {
        String keystoreType = "JKS";
        String keystorePassword = "";
        String keyAlias;
        String privateKeyPassword = "";
        String keystoreUri;
    }

    private static final String C14N_11 = "http://www.w3.org/2006/12/xml-c14n11";
    private static final String C14N_11_WITH_COMMENTS = C14N_11 + "#WithComments";

    /**
     * Resolves canonicalization algorithm names to XML Signature URIs.
     *
     * <p>Supports the 1.0 variants from the original EXPath spec and the 1.1 variants
     * from the <a href="https://github.com/claudius108/expath-cg/blob/master/specs/crypto/crypto-new.html">
     * 2018 CG spec</a> (§ generate-signature, canonicalization-algorithm parameter).</p>
     */
    private String resolveCanonicalization(final String name) throws XPathException {
        return switch (name.toLowerCase()) {
            case "inclusive", "inclusive-1.0" -> CanonicalizationMethod.INCLUSIVE;
            case "inclusive-with-comments", "inclusive-with-comments-1.0" ->
                    CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
            case "inclusive-1.1" -> C14N_11;
            case "inclusive-with-comments-1.1" -> C14N_11_WITH_COMMENTS;
            case "exclusive" -> CanonicalizationMethod.EXCLUSIVE;
            case "exclusive-with-comments" -> CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS;
            default -> throw new XPathException(this,
                    "Unsupported canonicalization: " + name);
        };
    }

    private String resolveDigestMethod(final String name) throws XPathException {
        return switch (name.toUpperCase()) {
            case "SHA1" -> DigestMethod.SHA1;
            case "SHA256" -> DigestMethod.SHA256;
            case "SHA512" -> DigestMethod.SHA512;
            default -> throw new XPathException(this,
                    "Unsupported digest algorithm: " + name + ". Use: SHA1, SHA256, SHA512.");
        };
    }

    /**
     * Resolves signature algorithm names to XML Signature URIs.
     *
     * <p>Accepts multiple naming conventions:</p>
     * <ul>
     *   <li>Underscore: {@code RSA_SHA1}, {@code DSA_SHA1}, {@code RSA_SHA256}</li>
     *   <li>Java-style (2018 CG spec): {@code RSAwithSHA1}, {@code DSAwithSHA1}</li>
     *   <li>Hyphenated: {@code RSA-SHA1}, {@code DSA-SHA1}</li>
     * </ul>
     */
    private String resolveSignatureMethod(final String name) throws XPathException {
        final String normalized = name.toUpperCase()
                .replace("-", "_")
                .replace("WITH", "_");
        return switch (normalized) {
            case "RSA_SHA1" -> SignatureMethod.RSA_SHA1;
            case "DSA_SHA1" -> SignatureMethod.DSA_SHA1;
            case "RSA_SHA256" -> SignatureMethod.RSA_SHA256;
            default -> throw new XPathException(this,
                    "Unsupported signature algorithm: " + name +
                            ". Use: RSA_SHA1, DSA_SHA1, RSA_SHA256 " +
                            "(also accepts RSAwithSHA1, DSAwithSHA1).");
        };
    }
}
