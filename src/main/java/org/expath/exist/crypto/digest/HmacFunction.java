/*
 * SPDX LGPL-2.1-or-later
 * Copyright (C) 2016 Claudius Teodorescu
 */
package org.expath.exist.crypto.digest;

import static org.exist.xquery.FunctionDSL.arities;
import static org.exist.xquery.FunctionDSL.arity;
import static org.exist.xquery.FunctionDSL.optManyParam;
import static org.exist.xquery.FunctionDSL.optParam;
import static org.exist.xquery.FunctionDSL.param;
import static org.exist.xquery.FunctionDSL.returns;
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
	private static FunctionParameterSequenceType FS_HMAC_PARAM_DATA = optManyParam("data", Type.ANY_ATOMIC_TYPE,
			"The data to be authenticated. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
	private static FunctionParameterSequenceType FS_HMAC_PARAM_KEY = optManyParam("key", Type.ANY_ATOMIC_TYPE,
			"The secret key used for calculating the authentication code. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
	private static FunctionParameterSequenceType FS_HMAC_PARAM_ALGORITHM = param("algorithm", Type.STRING,
			"The cryptographic hashing algorithm.");

	public final static FunctionSignature FS_HMAC[] = functionSignatures(FS_HMAC_NAME, "Hashes the input message.",
			returns(Type.STRING, "the HMAC value as an xs:base64Binary or xs:hexBinary string (default: base64)."),
			arities(arity(FS_HMAC_PARAM_DATA, FS_HMAC_PARAM_KEY, FS_HMAC_PARAM_ALGORITHM),
					arity(FS_HMAC_PARAM_DATA, FS_HMAC_PARAM_KEY, FS_HMAC_PARAM_ALGORITHM, optParam("encoding", Type.STRING,
							"The encoding of the output. The legal values are \"hex\" and \"base64\". The default value is \"base64\"."))));

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

			final String encoding;
			if (argsLength == 4) {
				encoding = args[3].getStringValue().isEmpty() ? "base64" : args[3].getStringValue();
			} else {
				encoding = "base64";
			}
			LOG.debug("encoding = {}", encoding);

			final String resultString;
			if (data.isLeft()) {
				try (final InputStream is = data.left().get()) {
					resultString = Hmac.hmac(is, secretKey, algorithm, encoding);
				}
				dataStreamClosed = true;
			} else {
				resultString = Hmac.hmac(data.right().get(), secretKey, algorithm, encoding);
			}
			LOG.debug("resultString = {}", resultString);

			result = new StringValue(resultString);
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

