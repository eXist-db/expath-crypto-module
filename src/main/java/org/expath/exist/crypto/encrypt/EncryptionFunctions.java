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
package org.expath.exist.crypto.encrypt;

import static org.exist.xquery.FunctionDSL.optParam;
import static org.exist.xquery.FunctionDSL.param;
import static org.exist.xquery.FunctionDSL.returns;
import static org.expath.exist.crypto.ExistExpathCryptoModule.functionSignature;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.util.Base64;

import javax.annotation.Nullable;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;
import org.expath.exist.crypto.EXpathCryptoException;
import org.expath.exist.crypto.ExistExpathCryptoModule;
import org.expath.exist.crypto.utils.Conversion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ro.kuberam.libs.java.crypto.CryptoError;
import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius
 *         Teodorescu</a>
 */
public class EncryptionFunctions extends BasicFunction {

	private static final Logger LOG = LoggerFactory.getLogger(EncryptionFunctions.class);

	private static final String FS_ENCRYPT_NAME = "encrypt";
	private static final String FS_DECRYPT_NAME = "decrypt";
	private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_DATA = param("data", Type.ATOMIC,
			"The data to be encrypted or decrypted. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary.");
	private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_SECRET_KEY = param("secret-key", Type.STRING,
			"The secret key used for encryption or decryption, as string.");
	private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM = param("algorithm",
			Type.STRING, "The cryptographic algorithm used for encryption or decryption.");
	private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_IV = optParam("iv", Type.STRING,
			"The initialization vector.");
	private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_PROVIDER = optParam("provider", Type.STRING,
			"The cryptographic provider.");

	public final static FunctionSignature FS_ENCRYPT = functionSignature(FS_ENCRYPT_NAME, "Encrypts the input string.",
			returns(Type.STRING, "the encrypted data."), FS_ENCRYPT_PARAM_DATA,
			param("encryption-type", Type.STRING,
					"The type of encryption. Legal values: 'symmetric', and 'asymmetric'."),
			FS_ENCRYPT_PARAM_SECRET_KEY, FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM, FS_ENCRYPT_PARAM_IV,
			FS_ENCRYPT_PARAM_PROVIDER);

	public final static FunctionSignature FS_DECRYPT = functionSignature(FS_DECRYPT_NAME, "Decrypts the input string.",
			returns(Type.STRING, "the decrypted data."), FS_ENCRYPT_PARAM_DATA,
			param("decryption-type", Type.STRING,
					"The type of decryption. Legal values: 'symmetric', and 'asymmetric'."),
			FS_ENCRYPT_PARAM_SECRET_KEY, FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM, FS_ENCRYPT_PARAM_IV,
			FS_ENCRYPT_PARAM_PROVIDER);

	public EncryptionFunctions(final XQueryContext context, final FunctionSignature signature) {
		super(context, signature);
	}

	@Override
	public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
		byte[] data;
		final CryptType cryptType = CryptType.valueOf(args[1].getStringValue().toUpperCase());
		final String secretKey = args[2].getStringValue();
		final String algorithm = args[3].getStringValue();
		@Nullable
		final String iv = args.length >= 5 && !args[4].isEmpty() ? args[4].getStringValue() : null;
		@Nullable
		final String provider = args.length >= 6 && !args[5].isEmpty() ? args[5].getStringValue() : null;

		switch (getName().getLocalPart()) {
		case FS_ENCRYPT_NAME:
			try {
				data = Conversion.toByteArray(Conversion.sequence2javaTypes(args[0]));
			} catch (IOException e) {
				throw new EXpathCryptoException(this, e);
			}
			return encrypt(data, cryptType, secretKey, algorithm, iv, provider);

		case FS_DECRYPT_NAME:
			data = Base64.getDecoder().decode(args[0].itemAt(0).getStringValue());
			return decrypt(data, cryptType, secretKey, algorithm, iv, provider);

		default:
			throw new EXpathCryptoException(this, ExistExpathCryptoModule.NO_FUNCTION,
					"No function: " + getName() + "#" + getSignature().getArgumentCount());
		}
	}

	private Sequence encrypt(byte[] data, CryptType encryptType, String secretKey, String algorithm,
			@Nullable String iv, @Nullable String provider) throws XPathException {
		try {
			byte[] resultBytes = null;

			switch (encryptType) {
			case SYMMETRIC:
				resultBytes = SymmetricEncryption.encrypt(data, secretKey, algorithm, iv, provider);
				break;

			case ASYMMETRIC:
				// encrypted = AsymmetricEncryption.encrypt(is, secretKey, algorithm);
				break;

			default:
				throw new EXpathCryptoException(this, CryptoError.ENCRYPTION_TYPE);
			}
			String result = Base64.getEncoder().encodeToString(resultBytes);
			LOG.debug("encrypt result = {}", result);

			return new StringValue(result);
		} catch (

		CryptoException e) {
			throw new EXpathCryptoException(this, e.getCryptoError());
		} catch (IOException e) {
			throw new EXpathCryptoException(this, e);
		}
	}

	private Sequence decrypt(byte[] data, CryptType decryptType, String secretKey, String algorithm,
			@Nullable String iv, @Nullable String provider) throws XPathException {
		try {
			byte[] resultBytes = null;

			switch (decryptType) {
			case SYMMETRIC:
				resultBytes = SymmetricEncryption.decrypt(data, secretKey, algorithm, iv, provider);
				break;

			case ASYMMETRIC:
				// decrypted = AsymmetricEncryption.decrypt(is, secretKey, algorithm, iv,
				// provider);
				break;

			default:
				throw new EXpathCryptoException(this, CryptoError.DECRYPTION_TYPE);
			}

			String result = new String(resultBytes, UTF_8);
			LOG.debug("decrypt result = {}", result);

			return new StringValue(result);
		} catch (CryptoException e) {
			throw new EXpathCryptoException(this, e.getCryptoError());
		} catch (IOException e) {
			throw new EXpathCryptoException(this, e);
		}
	}

	private enum CryptType {
		SYMMETRIC, ASYMMETRIC
	}
}

// ByteArrayOutputStream resultBaos = new ByteArrayOutputStream();
// final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
// int read = -1;
// while ((read = input.read(buf)) > -1) {
// byte[] tmpBuffer = cipher.update(buf, 0, read);
// resultBaos.write(tmpBuffer);
// }
