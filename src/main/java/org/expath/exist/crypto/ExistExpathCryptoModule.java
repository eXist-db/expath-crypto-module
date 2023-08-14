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
package org.expath.exist.crypto;

import java.util.List;
import java.util.Map;

import org.exist.dom.QName;
import org.exist.xquery.AbstractInternalModule;
import org.exist.xquery.FunctionDSL;
import org.exist.xquery.FunctionDef;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.ErrorCodes.ErrorCode;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.FunctionReturnSequenceType;
import org.expath.exist.crypto.digest.HashFunction;
import org.expath.exist.crypto.digest.HmacFunction;
import org.expath.exist.crypto.digitalSignature.GenerateSignatureFunction;
import org.expath.exist.crypto.digitalSignature.ValidateSignatureFunction;
import org.expath.exist.crypto.encrypt.EncryptionFunctions;

import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.ExpathCryptoModule;

import static org.exist.xquery.FunctionDSL.functionDefs;

/**
 * Implements the module definition.
 *
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class ExistExpathCryptoModule extends AbstractInternalModule {

	public static final String NAMESPACE_URI = ExpathCryptoModule.NAMESPACE_URI;
	public static final String PREFIX = ExpathCryptoModule.PREFIX;

	public final static String INCLUSION_DATE = "2011-03-24";
	public final static String RELEASED_IN_VERSION = "eXist-1.5";

	public final static ErrorCode NO_FUNCTION = new ExpathCryptoErrorCode("NO_FUNCTION", "No function");

	private final static FunctionDef[] functions = functionDefs(
			functionDefs(HashFunction.class, HashFunction.FS_HASH),
			functionDefs(HashFunction.class, HashFunction.FS_HASH_PROVIDERS),
			functionDefs(HashFunction.class, HashFunction.FS_HASH_ALGORITHMS),
			functionDefs(HmacFunction.class, HmacFunction.FS_HMAC),
			functionDefs(GenerateSignatureFunction.class, GenerateSignatureFunction.FS_GENERATE_SIGNATURE),
			functionDefs(ValidateSignatureFunction.class, ValidateSignatureFunction.FS_VALIDATE_SIGNATURE),
			functionDefs(EncryptionFunctions.class, EncryptionFunctions.FS_ENCRYPT, EncryptionFunctions.FS_DECRYPT)
	);

	public ExistExpathCryptoModule(final Map<String, List<? extends Object>> parameters) throws Exception {
		super(functions, parameters);
	}

	@Override
	public String getNamespaceURI() {
		return NAMESPACE_URI;
	}

	@Override
	public String getDefaultPrefix() {
		return PREFIX;
	}

	@Override
	public String getDescription() {
		return ExpathCryptoModule.MODULE_DESCRIPTION;
	}

	@Override
	public String getReleaseVersion() {
		return RELEASED_IN_VERSION;
	}

	public static FunctionSignature functionSignature(final String name, final String description,
			final FunctionReturnSequenceType returnType, final FunctionParameterSequenceType... paramTypes) {
		return FunctionDSL.functionSignature(new QName(name, NAMESPACE_URI, PREFIX), description, returnType, paramTypes);
	}

	public static FunctionSignature[] functionSignatures(final String name, final String description,
			final FunctionReturnSequenceType returnType, final FunctionParameterSequenceType[][] variableParamTypes) {
		return FunctionDSL.functionSignatures(new QName(name, NAMESPACE_URI, PREFIX), description, returnType,
				variableParamTypes);
	}
}
