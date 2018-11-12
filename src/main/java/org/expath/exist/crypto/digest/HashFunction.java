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

/**
 * Implements the crypto:hash() function for eXist.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.functions.map.MapType;
import org.exist.xquery.value.*;
import org.expath.exist.crypto.EXpathCryptoException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.digest.Hash;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.functionSignature;

public class HashFunction extends BasicFunction {

	private static final Logger LOG = LoggerFactory.getLogger(HashFunction.class);

	private static final String FS_HASH_NAME = "hash";
	private static final FunctionParameterSequenceType FS_HASH_PARAM_DATA = param("data", Type.ANY_TYPE,
			"The data to be hashed.");
	private static final FunctionParameterSequenceType FS_HASH_PARAM_ALGORITHM = param("algorithm", Type.STRING,
			"The cryptographic hashing algorithm.");
	private static final FunctionParameterSequenceType FS_HASH_PARAM_PROVIDER = param("provider", Type.STRING,
			"The cryptographic hashing algorithm provider.");

	public static final FunctionSignature FS_HASH[] = functionSignatures(
			FS_HASH_NAME,
			"resulting hash value, as string.",
			returnsOptMany(Type.BYTE),
			arities(
					arity(
							FS_HASH_PARAM_DATA,
							FS_HASH_PARAM_ALGORITHM
					),
					arity(
							FS_HASH_PARAM_DATA,
							FS_HASH_PARAM_ALGORITHM,
							param("encoding", Type.STRING, "The encoding of the output. The legal values are \"hex\" and \"base64\". The default value is \"base64\".")
					),
					arity(
							FS_HASH_PARAM_DATA,
							FS_HASH_PARAM_ALGORITHM,
							param("encoding", Type.STRING, "The encoding of the output. The legal values are \"hex\" and \"base64\". The default value is \"base64\"."),
							FS_HASH_PARAM_PROVIDER
					)
			)
	);

	private static final String FS_HASH_PROVIDERS_NAME = "hash-providers";
	public static final FunctionSignature FS_HASH_PROVIDERS = functionSignature(
			FS_HASH_PROVIDERS_NAME,
			"Gets the names of all the hash providers",
			returnsOptMany(Type.STRING)
	);

	private static final String FS_HASH_ALGORITHMS_NAME = "hash-algorithms";
	public static final FunctionSignature FS_HASH_ALGORITHMS[] = {
			functionSignature(
					FS_HASH_ALGORITHMS_NAME,
					"Gets the names of all the hash providers",
					returnsOptMany(Type.STRING)
			),
			functionSignature(
					FS_HASH_ALGORITHMS_NAME,
					"Gets the names of all the hash providers",
					returns(Type.MAP),
					param("provider-name", Type.STRING, "The name of the hash provider.")
			)
	};

	public HashFunction(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {

		if (isCalledAs(FS_HASH_NAME)) {
			return hash(args);

		} else if (isCalledAs(FS_HASH_PROVIDERS_NAME)) {
			final ValueSequence providers = new ValueSequence();
			for (final String provider : Hash.listProviders()) {
				providers.add(new StringValue(provider));
			}
			return providers;

		} else if (isCalledAs(FS_HASH_ALGORITHMS_NAME)) {
			if (args.length == 1) {
				final String providerName = args[0].getStringValue();
				final ValueSequence algorithmNames = new ValueSequence();
				for (final String algorithmName : Hash.listAlgorithms(providerName)) {
					algorithmNames.add(new StringValue(algorithmName));
				}
				return algorithmNames;

			} else {
				final MapType mapType = new MapType(this.context);
				for(final Map.Entry<String, Set<String>> providerAlgorithms : Hash.listAlgorithms().entrySet()) {
					final ValueSequence algorithmNames = new ValueSequence();
					for (final String algorithmName : providerAlgorithms.getValue()) {
						algorithmNames.add(new StringValue(algorithmName));
					}
					mapType.add(new StringValue(providerAlgorithms.getKey()), algorithmNames);
				}
				return mapType;
			}
		} else {
			throw new XPathException(this, "Unknown function name");
		}
	}

	private Sequence hash(final Sequence[] args) throws XPathException {
		final int inputType = args[0].itemAt(0).getType();
		final String hashAlgorithm = args[1].getStringValue();
		final String encoding;
		if (args.length == 2) {
			encoding = "base64";
		} else {
			encoding = args[2].getStringValue().isEmpty() ? "base64" : args[2].getStringValue();
		}
        String provider = null;
		if (args.length == 4) {
			provider = args[3].getStringValue();
		}

		LOG.debug("encoding = {}", encoding);

		final Sequence result;
		if (inputType == Type.STRING || inputType == Type.ELEMENT || inputType == Type.DOCUMENT) {
			try {
				result = new StringValue(Hash.hashString(args[0].getStringValue(), hashAlgorithm, provider, encoding));
			} catch (CryptoException e) {
				throw new EXpathCryptoException(this, e.getCryptoError());
			}
		} else if (inputType == Type.BASE64_BINARY || inputType == Type.HEX_BINARY) {
			try {
				final BinaryValue binaryValue = (BinaryValue) args[0].itemAt(0);
				try (final InputStream is = binaryValue.getInputStream()) {
					result = new StringValue(Hash.hashBinary(is, hashAlgorithm, provider, encoding));
				}
			} catch (CryptoException e) {
				throw new EXpathCryptoException(this, e.getCryptoError());
			} catch (IOException e) {
				throw new EXpathCryptoException(this, e);
			}
		} else {
			result = Sequence.EMPTY_SEQUENCE;
		}

		return result;
	}
}
