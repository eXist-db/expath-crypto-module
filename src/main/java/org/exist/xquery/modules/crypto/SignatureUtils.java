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

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.exist.dom.memtree.DocumentBuilderReceiver;
import org.exist.dom.memtree.MemTreeBuilder;
import org.exist.storage.DBBroker;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

/**
 * Utility methods for converting between eXist in-memory nodes and W3C DOM Documents,
 * needed by the XML Digital Signature API which operates on DOM.
 *
 * <p>Both directions use the same serialization path: JAXP identity Transformer with
 * {@code indent=no}, then JAXP SAX parse. This guarantees that the XML content is
 * byte-identical through round-trips, which is critical for XML signature validation.</p>
 */
final class SignatureUtils {

    private SignatureUtils() {
        // utility class
    }

    /**
     * Converts an eXist NodeValue to a W3C DOM Document.
     *
     * <p>Uses JAXP identity Transformer (indent=no) to serialize the eXist node to XML,
     * then parses with a namespace-aware DOM parser.</p>
     */
    static Document nodeToDomDocument(final DBBroker broker, final NodeValue node)
            throws XPathException {
        try {
            // Use eXist's Serializer with explicit no-indent to get canonical XML
            final org.exist.storage.serializers.Serializer serializer = broker.borrowSerializer();
            final String xml;
            try {
                final StringWriter writer = new StringWriter();
                serializer.reset();
                final java.util.Properties props = new java.util.Properties();
                props.setProperty(OutputKeys.INDENT, "no");
                props.setProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                props.setProperty(
                        org.exist.storage.serializers.Serializer.GENERATE_DOC_EVENTS, "false");
                serializer.setProperties(props);
                serializer.serialize(node, writer, false);
                xml = writer.toString();
            } finally {
                broker.returnSerializer(serializer);
            }

            // Parse into a standard W3C DOM
            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            final DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new InputSource(new StringReader(xml)));
        } catch (final Exception e) {
            throw new XPathException("Failed to convert eXist node to DOM: " + e.getMessage(), e);
        }
    }

    /**
     * Serializes a W3C DOM node to an XML string using the JDK's built-in
     * identity Transformer with {@code indent=no}.
     */
    private static String serializeDomToString(final org.w3c.dom.Node domNode)
            throws XPathException {
        try {
            final TransformerFactory tf = TransformerFactory.newInstance(
                    "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl",
                    SignatureUtils.class.getClassLoader());
            final Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            final StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(domNode), new StreamResult(writer));
            return writer.toString();
        } catch (final Exception e) {
            throw new XPathException("Failed to serialize DOM: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a W3C DOM Document to an eXist in-memory document.
     *
     * <p>Serializes the DOM to a string (no indentation) via JAXP identity Transformer,
     * then parses into eXist's memtree via SAX. This ensures the XML is identical to
     * what {@link #nodeToDomDocument} would produce from the resulting memtree.</p>
     */
    static Sequence domToMemTree(final XQueryContext context, final Document domDoc)
            throws XPathException {
        try {
            // Serialize DOM to string with no indentation using JDK Transformer
            final String xml = serializeDomToString(domDoc);

            // Parse XML string directly into eXist memtree via SAX
            final SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setNamespaceAware(true);
            final SAXParser saxParser = spf.newSAXParser();
            final XMLReader reader = saxParser.getXMLReader();

            context.pushDocumentContext();
            try {
                final MemTreeBuilder builder = context.getDocumentBuilder();
                builder.startDocument();
                final DocumentBuilderReceiver receiver = new DocumentBuilderReceiver(builder, true);
                reader.setContentHandler(receiver);
                reader.parse(new InputSource(new StringReader(xml)));
                builder.endDocument();
                return builder.getDocument();
            } finally {
                context.popDocumentContext();
            }
        } catch (final Exception e) {
            throw new XPathException(
                    "Failed to convert DOM to eXist memtree: " + e.getMessage(), e);
        }
    }
}
