/**
 * eXist-db EXPath Cryptographic library
 * eXist-db wrapper for EXPath Cryptographic Java library
 * Copyright (C) 2016 Kuberam
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
import java.io.Reader;
import java.io.StringReader;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.storage.serializers.Serializer;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BooleanValue;
import org.exist.xquery.value.NodeValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.Type;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;

import ro.kuberam.libs.java.crypto.digitalSignature.ValidateXmlSignature;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

/**
 * Cryptographic extension functions.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */
public class ValidateSignatureFunction extends BasicFunction {

    private static final Logger LOG = LogManager.getLogger(ValidateSignatureFunction.class);

    public final static FunctionSignature FS_VALIDATE_SIGNATURE = functionSignature(
        "validate-signature",
        "This function validates an XML Digital Signature.",
        returns(Type.BOOLEAN, "boolean value true() if the signature is valid, otherwise return value false()."),
        param("data", Type.NODE, "The enveloped, enveloping, or detached signature.")
    );

    public ValidateSignatureFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    private static final Properties defaultOutputKeysProperties = new Properties();
    static {
        defaultOutputKeysProperties.setProperty(OutputKeys.INDENT, "no");
        defaultOutputKeysProperties.setProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        defaultOutputKeysProperties.setProperty(OutputKeys.ENCODING, "UTF-8");
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        if (args[0].isEmpty()) {
            return Sequence.EMPTY_SEQUENCE;
        }

        //get and process the input document or node to InputStream, in order to be transformed into DOM Document
        final Serializer serializer = context.getBroker().getSerializer();
        serializer.reset();

        final Properties outputProperties = new Properties(defaultOutputKeysProperties);
        try {
            serializer.setProperties(outputProperties);
        } catch (final SAXNotRecognizedException | SAXNotSupportedException ex) {
            LOG.error(ex.getMessage(), ex);
        }

        //initialize the document builder
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = null;
        try {
            db = dbf.newDocumentBuilder();
        } catch (final ParserConfigurationException ex) {
            LOG.error(ex.getMessage(), ex);
        }

        //process the input string to DOM document
        Document inputDOMDoc = null;
        try(final Reader reader = new StringReader(serializer.serialize((NodeValue) args[0].itemAt(0)))) {
            inputDOMDoc = db.parse(new InputSource(reader));
        } catch (final SAXException | IOException ex) {
            LOG.error(ex.getMessage(), ex);
        }

        //validate the signature
        Boolean isValid = false;
        try {
            isValid = ValidateXmlSignature.validate(inputDOMDoc);
//            	isValid = ValidateXmlSignature.validate((Document)args[0].itemAt(0));
        } catch (final Exception ex) {
            throw new XPathException(ex.getMessage());
        }

        return new BooleanValue(isValid);
    }
}