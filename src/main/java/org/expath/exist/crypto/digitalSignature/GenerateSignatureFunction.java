/**
 * eXist-db EXPath Cryptographic library
 * eXist-db wrapper for EXPath Cryptographic Java library
 * Copyright (C) 2016 Claudius Teodorescu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
package org.expath.exist.crypto.digitalSignature;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URISyntaxException;

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.Namespaces;
import org.exist.dom.memtree.SAXAdapter;
import org.exist.dom.persistent.BinaryDocument;
import org.exist.dom.persistent.DocumentImpl;
import org.exist.security.PermissionDeniedException;
import org.exist.storage.lock.Lock;
import org.exist.storage.serializers.Serializer;
import org.exist.validation.internal.node.NodeInputStream;
import org.exist.xmldb.XmldbURI;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.Type;
import org.expath.exist.crypto.EXpathCryptoException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;
import ro.kuberam.libs.java.crypto.digitalSignature.GenerateXmlSignature;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

/**
 * @author Claudius Teodorescu (claudius.teodorescu@gmail.com)
 */
public class GenerateSignatureFunction extends BasicFunction {

	private static final Logger LOG = LogManager.getLogger(GenerateSignatureFunction.class);

	private static String FS_GENERATE_SIGNATURE_NAME = "generate-signature";
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_DATA = param("data", Type.NODE,
			"The document to be signed.");
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_CANONICALIZATION_ALGORITHM = param(
			"canonicalization-algorithm", Type.STRING, "Canonicalization Algorithm.");
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_DIGEST_ALGORITHM = param(
			"digest-algorithm", Type.STRING, ExpathCryptoModule.DIGEST_ALGORITHM);
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_ALGORITHM = param(
			"signature-algorithm", Type.STRING, ExpathCryptoModule.SIGNATURE_ALGORITHM);
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_NAMESPACE_PREFIX = param(
			"signature-namespace-prefix", Type.STRING, "The namespace prefix for signature.");
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_TYPE = param(
			"signature-type", Type.STRING, ExpathCryptoModule.SIGNATURE_TYPE);
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_DIGITAL_CERTIFICATE = param(
			"digital-certificate", Type.ANY_TYPE, ExpathCryptoModule.digitalCertificateDetailsDescription);
	private static FunctionParameterSequenceType FS_GENERATE_SIGNATURE_PARAM_XPATH = param("xpath-expression",
			Type.ANY_TYPE, "The XPath expression used for selecting the subset to be signed.");

	public static final FunctionSignature FS_GENERATE_SIGNATURE[] = functionSignatures(FS_GENERATE_SIGNATURE_NAME,
			"Generate an XML digital signature based on generated key pair. This signature is for the whole document.",
			returns(Type.NODE, "the signed document (or signature) as node()."),
			arities(arity(FS_GENERATE_SIGNATURE_PARAM_DATA, FS_GENERATE_SIGNATURE_PARAM_CANONICALIZATION_ALGORITHM,
					FS_GENERATE_SIGNATURE_PARAM_DIGEST_ALGORITHM, FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_ALGORITHM,
					FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_NAMESPACE_PREFIX, FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_TYPE),
					arity(FS_GENERATE_SIGNATURE_PARAM_DATA, FS_GENERATE_SIGNATURE_PARAM_CANONICALIZATION_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_DIGEST_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_NAMESPACE_PREFIX,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_TYPE, FS_GENERATE_SIGNATURE_PARAM_XPATH),
					arity(FS_GENERATE_SIGNATURE_PARAM_DATA, FS_GENERATE_SIGNATURE_PARAM_CANONICALIZATION_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_DIGEST_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_NAMESPACE_PREFIX,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_TYPE,
							FS_GENERATE_SIGNATURE_PARAM_DIGITAL_CERTIFICATE),
					arity(FS_GENERATE_SIGNATURE_PARAM_DATA, FS_GENERATE_SIGNATURE_PARAM_CANONICALIZATION_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_DIGEST_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_ALGORITHM,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_NAMESPACE_PREFIX,
							FS_GENERATE_SIGNATURE_PARAM_SIGNATURE_TYPE, FS_GENERATE_SIGNATURE_PARAM_XPATH,
							FS_GENERATE_SIGNATURE_PARAM_DIGITAL_CERTIFICATE)));

	private static final String certificateRootElementName = "digital-certificate";
	private static final String[] certificateChildElementNames = { "keystore-type", "keystore-password", "key-alias",
			"private-key-password", "keystore-uri" };

	public GenerateSignatureFunction(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
		Serializer serializer = context.getBroker().getSerializer();
		NodeValue inputNode = (NodeValue) args[0].itemAt(0);
		Document inputDOMDoc;

		try (InputStream inputNodeStream = new NodeInputStream(serializer, inputNode)) {
			inputDOMDoc = inputStreamToDocument(inputNodeStream);
		} catch (IOException e) {
			throw new EXpathCryptoException(this, e);
		}

		String canonicalizationAlgorithm = args[1].getStringValue();
		String digestAlgorithm = args[2].getStringValue();
		String signatureAlgorithm = args[3].getStringValue();
		String signatureNamespacePrefix = args[4].getStringValue();
		String signatureType = args[5].getStringValue();

		String signatureString = null;
		Document signatureDocument = null;

		// get the XPath expression and/or the certificate's details
		String xpathExprString = null;
		String[] certificateDetails = new String[5];
		certificateDetails[0] = "";
		InputStream keyStoreInputStream = null;

		try {

			// function with 7 arguments
			if (args.length == 7) {
				if (args[6].itemAt(0).getType() == 22) {
					xpathExprString = args[6].getStringValue();
				} else if (args[6].itemAt(0).getType() == 1) {
					final Node certificateDetailsNode = ((NodeValue) args[6].itemAt(0)).getNode();
					// get the certificate details
					certificateDetails = getDigitalCertificateDetails(certificateDetails, certificateDetailsNode);
					// get the keystore InputStream
					keyStoreInputStream = getKeyStoreInputStream(certificateDetails[4]);
				}
			}

			// function with 8 arguments
			if (args.length == 8) {
				xpathExprString = args[6].getStringValue();
				final Node certificateDetailsNode = ((NodeValue) args[7].itemAt(0)).getNode();
				// get the certificate details
				certificateDetails = getDigitalCertificateDetails(certificateDetails, certificateDetailsNode);
				// get the keystore InputStream
				keyStoreInputStream = getKeyStoreInputStream(certificateDetails[4]);
			}

			signatureString = GenerateXmlSignature.generate(inputDOMDoc, canonicalizationAlgorithm, digestAlgorithm,
					signatureAlgorithm, signatureNamespacePrefix, signatureType, xpathExprString, certificateDetails,
					keyStoreInputStream);

			signatureDocument = stringToDocument(signatureString);

			return (Sequence) signatureDocument;
		} catch (CryptoException | IOException | XMLSignatureException e) {
			throw new EXpathCryptoException(this, e);
		} finally {
			if (keyStoreInputStream != null) {
				try {
					keyStoreInputStream.close();
				} catch (final IOException e) {
					throw new EXpathCryptoException(this, e);
				}
			}
		}

	}

	private Document stringToDocument(final String signatureString) throws XPathException {
		// process the output (signed) document from string to node()
		try {
			final SAXParserFactory factory = SAXParserFactory.newInstance();
			factory.setNamespaceAware(true);
			final SAXParser parser = factory.newSAXParser();
			final XMLReader xr = parser.getXMLReader();
			final SAXAdapter adapter = new SAXAdapter(context);
			xr.setContentHandler(adapter);
			xr.setProperty(Namespaces.SAX_LEXICAL_HANDLER, adapter);
			xr.parse(new InputSource(new StringReader(signatureString)));

			return adapter.getDocument();

		} catch (final ParserConfigurationException e) {
			throw new XPathException(this, "Error while constructing XML parser: " + e.getMessage());
		} catch (final SAXException | IOException e) {
			throw new XPathException(this, "Error while parsing XML: " + e.getMessage());
		}
	}

	private String[] getDigitalCertificateDetails(final String[] certificateDetails, final Node certificateDetailsNode)
			throws CryptoException {
		if (!certificateDetailsNode.getNodeName().equals(certificateRootElementName)) {
			throw new CryptoException(CryptoError.SIGNATURE_ELEMENT);
			// TODO: here was err:CX05 The root element of argument
			// $digital-certificate must have the name 'digital-certificate'.
		}

		final NodeList certificateDetailsNodeList = certificateDetailsNode.getChildNodes();
		for (int i = 0, il = certificateDetailsNodeList.getLength(); i < il; i++) {
			final Node child = certificateDetailsNodeList.item(i);
			if (child.getNodeName().equals(certificateChildElementNames[i])) {
				certificateDetails[i] = child.getFirstChild().getNodeValue();
			} else {
				throw new CryptoException(CryptoError.SIGNATURE_ELEMENT);
				// TODO: here was err:CX05 The root element of argument
				// $digital-certificate must have the name
				// 'digital-certificate'.
			}
		}
		return certificateDetails;
	}

	private InputStream getKeyStoreInputStream(final String keystoreURI) throws CryptoException {
		// get the keystore as InputStream
		try {
			DocumentImpl keyStoreDoc = null;
			try {
				keyStoreDoc = context.getBroker().getXMLResource(XmldbURI.xmldbUriFor(keystoreURI),
						Lock.LockMode.READ_LOCK);
				if (keyStoreDoc == null) {
					throw new CryptoException(CryptoError.UNREADABLE_KEYSTORE);
				}

				final BinaryDocument keyStoreBinaryDoc = (BinaryDocument) keyStoreDoc;
				try {
					return context.getBroker().getBinaryResource(keyStoreBinaryDoc);
				} catch (final IOException e) {
					throw new CryptoException(CryptoError.UNREADABLE_KEYSTORE, e);
				}

			} catch (final PermissionDeniedException e) {
				LOG.error(CryptoError.DENIED_KEYSTORE.getDescription());
				return null;
			} finally {
				keyStoreDoc.getUpdateLock().release(Lock.LockMode.READ_LOCK);
			}
		} catch (final URISyntaxException e) {
			LOG.error(CryptoError.KEYSTORE_URL.getDescription());
			return null;
		}
	}

	private Document inputStreamToDocument(final InputStream inputStream) {
		// initialize the document builder
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = null;
		try {
			db = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException ex) {
		}

		// convert data to DOM document
		Document document = null;
		try {
			document = db.parse(inputStream);
		} catch (SAXException | IOException ex) {
			ex.getMessage();
		}

		return document;
	}
}