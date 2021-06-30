/*
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
package org.expath.exist.crypto.digest;

import static org.exist.xquery.FunctionDSL.arities;
import static org.exist.xquery.FunctionDSL.arity;
import static org.exist.xquery.FunctionDSL.optManyParam;
import static org.exist.xquery.FunctionDSL.param;
import static org.exist.xquery.FunctionDSL.returnsOptMany;
import static org.expath.exist.crypto.ExistExpathCryptoModule.functionSignatures;

import java.io.IOException;
import java.io.InputStream;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;
import org.expath.exist.crypto.EXpathCryptoException;
import org.expath.exist.crypto.utils.Conversion;

import com.evolvedbinary.j8fu.Either;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.digest.Hmac;

public class HmacFunction extends BasicFunction {

	private static final Logger LOG = LoggerFactory.getLogger(HmacFunction.class);

	private static String FS_HMAC_NAME = "hmac";
	private static FunctionParameterSequenceType FS_HMAC_PARAM_DATA = optManyParam("data", Type.ATOMIC,
			"The data to be authenticated. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
	private static FunctionParameterSequenceType FS_HMAC_PARAM_KEY = optManyParam("key", Type.ATOMIC,
			"The secret key used for calculating the authentication code. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
	private static FunctionParameterSequenceType FS_HMAC_PARAM_ALGORITHM = param("algorithm", Type.STRING,
			"The cryptographic hashing algorithm.");

	public final static FunctionSignature FS_HMAC[] = functionSignatures(FS_HMAC_NAME, "Hashes the input message.",
			returnsOptMany(Type.BYTE),
			arities(arity(FS_HMAC_PARAM_DATA, FS_HMAC_PARAM_KEY, FS_HMAC_PARAM_ALGORITHM),
					arity(FS_HMAC_PARAM_DATA, FS_HMAC_PARAM_KEY, FS_HMAC_PARAM_ALGORITHM, param("encoding", Type.STRING,
							"The encoding of the output. The legal values are \"hex\" and \"base64\". The result is generated accordingly as xs:base64Binary string or xs:hexBinary string."))));

	public HmacFunction(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
		final int argsLength = args.length;
		LOG.debug("argsLength = {}", argsLength);
		LOG.debug("data item count = {}", args[0].getItemCount());

		final Sequence result;
		Either<InputStream, byte[]> data = null;
		boolean dataStreamClosed = false;

		try {
			data = Conversion.sequence2javaTypes(args[0]);

			final byte[] secretKey = Conversion.toByteArray(Conversion.sequence2javaTypes(args[1]));

			final String algorithm = args[2].getStringValue();
			LOG.debug("algorithm = {}", algorithm);

			if (argsLength == 3) {
				final byte[] resultBytes;
				if (data.isLeft()) {
					try (final InputStream is = data.left().get()) {
						resultBytes = Hmac.hmac(is, secretKey, algorithm);
					}
					dataStreamClosed = true;
				} else {
					resultBytes = Hmac.hmac(data.right().get(), secretKey, algorithm);
				}

				result = Conversion.byteArrayToIntegerSequence(resultBytes);
			} else if (argsLength == 4) {
				final String encoding = args[3].getStringValue().isEmpty() ? "base64" : args[3].getStringValue();
				LOG.debug("encoding = {}", encoding);

				final String resultString;

				if (data.isLeft()) {
					try (final InputStream is = data.left().get()) {
						resultString = Hmac.hmac(is, secretKey, algorithm, encoding);
					}
				} else {
					resultString = Hmac.hmac(data.right().get(), secretKey, algorithm, encoding);
				}
				LOG.debug("resultString = {}", resultString);

				result = new StringValue(resultString);
			} else {
				result = Sequence.EMPTY_SEQUENCE;
			}
		} catch (CryptoException e) {
			throw new EXpathCryptoException(this, e.getCryptoError());
		} catch (IOException e) {
			throw new EXpathCryptoException(this, e);
		} finally {
			if (data != null && data.isLeft() && !dataStreamClosed) {
				try {
					data.left().get().close();
				} catch (IOException e) {
					throw new EXpathCryptoException(this, e);
				}
			}
		}

		return result;
	}
}

