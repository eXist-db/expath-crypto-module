/*
 *  eXist Java Cryptographic Extension
 *  Copyright (C) 2010 Claudius Teodorescu at http://kuberam.ro
 *
 *  Released under LGPL License - http://gnu.org/licenses/lgpl.html.
 *
 */

package org.expath.exist.crypto.digest;

/**
 * Implements the module definition.
 * 
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.exist.dom.QName;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.Cardinality;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.Base64BinaryValueType;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.BinaryValueFromInputStream;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.FunctionReturnSequenceType;
import org.exist.xquery.value.IntegerValue;
import org.exist.xquery.value.NumericValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.SequenceIterator;
import org.exist.xquery.value.SequenceType;
import org.exist.xquery.value.Type;
import org.exist.xquery.value.ValueSequence;
import org.expath.exist.crypto.ExistExpathCryptoModule;

import ro.kuberam.libs.java.crypto.digest.Hmac;

public class HmacFunction extends BasicFunction {

	private final static Logger logger = Logger.getLogger(HmacFunction.class);

	public final static FunctionSignature signatures[] = {
			new FunctionSignature(
					new QName("hmac", ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX),
					"Hashes the input message.",
					new SequenceType[] {
							new FunctionParameterSequenceType("data", Type.ATOMIC, Cardinality.ZERO_OR_MORE,
									"The data to be authenticated. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary."),
							new FunctionParameterSequenceType("secret-key", Type.ATOMIC, Cardinality.ZERO_OR_MORE,
									"The secret key used for calculating the authentication code. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary."),
							new FunctionParameterSequenceType("algorithm", Type.STRING, Cardinality.EXACTLY_ONE,
									"The cryptographic hashing algorithm.") },
					new FunctionReturnSequenceType(Type.BYTE, Cardinality.ZERO_OR_MORE,
							"hash-based message authentication code, as string.")),
			new FunctionSignature(
					new QName("hmac", ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX),
					"Hashes the input message.",
					new SequenceType[] {
							new FunctionParameterSequenceType("data", Type.ATOMIC, Cardinality.ZERO_OR_MORE,
									"The data to be authenticated. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary."),
							new FunctionParameterSequenceType("secret-key", Type.ATOMIC, Cardinality.ZERO_OR_MORE,
									"The secret key used for calculating the authentication code. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary."),
							new FunctionParameterSequenceType("algorithm", Type.STRING, Cardinality.EXACTLY_ONE,
									"The cryptographic hashing algorithm."),
							new FunctionParameterSequenceType("format", Type.STRING, Cardinality.EXACTLY_ONE,
									"The format of the output. The legal values are \"hex\" and \"base64\". The default value is \"base64\".") },
					new FunctionReturnSequenceType(Type.BASE64_BINARY, Cardinality.ZERO_OR_ONE,
							"hash-based message authentication code, as string.")) };

	public HmacFunction(XQueryContext context, FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(Sequence[] args, Sequence contextSequence) throws XPathException {
		Sequence result = Sequence.EMPTY_SEQUENCE;
		int argsLength = args.length;
		logger.debug("argsLength = " + argsLength);

		byte[] data = sequence2byteArray(args[0]);
		logger.debug("data item count = " + args[0].getItemCount());
		logger.debug("data = " + data);

		byte[] secretKey = sequence2byteArray(args[1]);
		logger.debug("secretKey item count = " + args[1].getItemCount());
		logger.debug("secretKey = " + secretKey);

		String algorithm = args[2].getStringValue();
		logger.debug("algorithm = " + algorithm);

		String encoding = "base64";
		if (args.length == 4) {
			encoding = args[3].getStringValue();
		}
		logger.debug("encoding = " + encoding);

		try {
			if (argsLength == 3) {
				byte[] resultBytes = Hmac.hmac(data, secretKey, algorithm);
				int resultBytesLength = resultBytes.length;
				logger.debug("resultBytesLength = " + resultBytesLength);
				logger.debug("resultBytes = " + Arrays.toString(resultBytes));

				result = new ValueSequence();
				for (int i = 0, il = resultBytesLength; i < il; i++) {
					result.add(new IntegerValue(resultBytes[i]));
				}
			}

			if (argsLength == 4) {
				String hmacResultString = Hmac.hmac(data, secretKey, algorithm, encoding);
				logger.debug("hmacResult = " + hmacResultString);

				result = BinaryValueFromInputStream.getInstance(context, new Base64BinaryValueType(),
						new ByteArrayInputStream(hmacResultString.getBytes(StandardCharsets.UTF_8)));
			}
		} catch (Exception ex) {
			throw new XPathException(ex.getMessage());
		}

		return result;
	}

	private byte[] sequence2byteArray(Sequence sequence) throws XPathException {
		final int itemCount = sequence.getItemCount();
		logger.debug("itemCount = " + itemCount);

		byte[] result = null;

		try {
			if (itemCount == 1) {
				final int itemType = sequence.itemAt(0).getType();

				switch (itemType) {
				case Type.STRING:
				case Type.ELEMENT:
				case Type.DOCUMENT:
					result = sequence.itemAt(0).getStringValue().getBytes(StandardCharsets.UTF_8);
					break;
				case Type.BASE64_BINARY:
					result = binaryValueToByte((BinaryValue) sequence.itemAt(0));
					break;
				}
			} else {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				
				int counter = 0;
				for (final SequenceIterator iterator = sequence.iterate(); iterator.hasNext(); counter++) {
					baos.write(((NumericValue) iterator.nextItem()).getInt());
				}
				logger.debug("counter = " + counter);
				
				result = baos.toByteArray();
			}
		} catch (Exception ex) {
			throw new XPathException(ex.getMessage());
		}

		return result;
	}

	private byte[] binaryValueToByte(BinaryValue binary) throws XPathException {
		final ByteArrayOutputStream os = new ByteArrayOutputStream();

		try {
			binary.streamBinaryTo(os);
			return os.toByteArray();
		} catch (final IOException ioe) {
			throw new XPathException(this, ioe);
		} finally {
			try {
				os.close();
			} catch (final IOException ex) {
			}
		}
	}
}
