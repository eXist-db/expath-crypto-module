/*
 * SPDX LGPL-2.1-or-later
 * Copyright (C) 2016 The eXist-db Authors
 */
package org.expath.exist.crypto.utils;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.SAXException;

import static javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING;

/**
 * Factory helpers that return JAXP parser factories hardened against
 * XML External Entity (XXE) attacks per
 * https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
 *
 * Signed XML documents do not legitimately reference external entities or
 * DOCTYPE declarations — entity references and the internal subset are
 * stripped during XML Canonicalization anyway — so disallowing DOCTYPE
 * outright is the appropriate default for this module.
 *
 * NOTE: eXist-db's per-call-site XXE hardening (e.g. in Configuration.java,
 * MimeTable.java) is NOT inherited here. The crypto module calls
 * {@code DocumentBuilderFactory.newInstance()} / {@code SAXParserFactory.newInstance()}
 * directly and so must apply its own protections.
 */
public final class SecureXmlParsers {

	private static final String DISALLOW_DOCTYPE_DECL =
			"http://apache.org/xml/features/disallow-doctype-decl";
	private static final String LOAD_EXTERNAL_DTD =
			"http://apache.org/xml/features/nonvalidating/load-external-dtd";
	private static final String EXTERNAL_GENERAL_ENTITIES =
			"http://xml.org/sax/features/external-general-entities";
	private static final String EXTERNAL_PARAMETER_ENTITIES =
			"http://xml.org/sax/features/external-parameter-entities";

	private SecureXmlParsers() { }

	/**
	 * @return a {@link DocumentBuilderFactory} that rejects DOCTYPE declarations
	 *         and refuses to resolve external entities.
	 */
	public static DocumentBuilderFactory newDocumentBuilderFactory()
			throws ParserConfigurationException {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature(FEATURE_SECURE_PROCESSING, true);
		dbf.setFeature(DISALLOW_DOCTYPE_DECL, true);
		dbf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		dbf.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		dbf.setFeature(LOAD_EXTERNAL_DTD, false);
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);
		return dbf;
	}

	/**
	 * @return a {@link SAXParserFactory} that rejects DOCTYPE declarations
	 *         and refuses to resolve external entities.
	 */
	public static SAXParserFactory newSAXParserFactory()
			throws ParserConfigurationException, SAXException {
		final SAXParserFactory spf = SAXParserFactory.newInstance();
		spf.setFeature(FEATURE_SECURE_PROCESSING, true);
		spf.setFeature(DISALLOW_DOCTYPE_DECL, true);
		spf.setFeature(EXTERNAL_GENERAL_ENTITIES, false);
		spf.setFeature(EXTERNAL_PARAMETER_ENTITIES, false);
		spf.setFeature(LOAD_EXTERNAL_DTD, false);
		spf.setXIncludeAware(false);
		return spf;
	}
}
