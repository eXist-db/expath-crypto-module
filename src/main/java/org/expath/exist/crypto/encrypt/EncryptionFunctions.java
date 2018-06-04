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
package org.expath.exist.crypto.encrypt;

import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.*;

import ro.kuberam.libs.java.crypto.CryptoException;
import ro.kuberam.libs.java.crypto.encrypt.AsymmetricEncryption;
import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;

import javax.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

/**
 * @author <a href="mailto:claudius.teodorescu@gmail.com">Claudius Teodorescu</a>
 */
public class EncryptionFunctions extends BasicFunction {

    private static final String FS_ENCRYPT_NAME = "encrypt";
    private static final String FS_DECRYPT_NAME = "decrypt";
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_DATA = param("data", Type.ATOMIC, "The data to be encrypted or decrypted. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_SECRET_KEY = param("secret-key", Type.STRING, "The secret key used for encryption or decryption, as string.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM = param("algorithm", Type.STRING, "The cryptographic algorithm used for encryption or decryption.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_IV = optParam("iv", Type.STRING, "The initialization vector.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_PROVIDER = optParam("provider", Type.STRING, "The cryptographic provider.");

    public final static FunctionSignature FS_ENCRYPT = functionSignature(
            FS_ENCRYPT_NAME,
            "Encrypts the input string.",
            returns(Type.STRING, "the encrypted data."),
            FS_ENCRYPT_PARAM_DATA,
            param("encryption-type", Type.STRING, "The type of encryption. Legal values: 'symmetric', and 'asymmetric'."),
            FS_ENCRYPT_PARAM_SECRET_KEY,
            FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM,
            FS_ENCRYPT_PARAM_IV,
            FS_ENCRYPT_PARAM_PROVIDER
    );

    public final static FunctionSignature FS_DECRYPT = functionSignature(
            FS_DECRYPT_NAME,
            "Decrypts the input string.",
            returns(Type.STRING, "the decrypted data."),
            FS_ENCRYPT_PARAM_DATA,
            param("decryption-type", Type.STRING, "The type of decryption. Legal values: 'symmetric', and 'asymmetric'."),
            FS_ENCRYPT_PARAM_SECRET_KEY,
            FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM,
            FS_ENCRYPT_PARAM_IV,
            FS_ENCRYPT_PARAM_PROVIDER
    );

    public EncryptionFunctions(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final Item data = args[0].itemAt(0);
        final CryptType cryptType = CryptType.valueOf(args[1].getStringValue().toUpperCase());
        final String secretKey = args[2].getStringValue();
        final String algorithm = args[3].getStringValue();
        @Nullable final String iv = args.length >= 5 && !args[4].isEmpty() ? args[4].getStringValue() : null;
        @Nullable final String provider = args.length >= 6 && !args[5].isEmpty() ? args[5].getStringValue() : null;

        switch (getName().getLocalPart()) {
            case FS_ENCRYPT_NAME:
                return encrypt(data, cryptType, secretKey, algorithm, iv, provider);

            case FS_DECRYPT_NAME:
                return decrypt(data, cryptType, secretKey, algorithm, iv, provider);

            default:
                throw new XPathException(this, "No function: " + getName() + "#" + getSignature().getArgumentCount());
        }
    }

    private Sequence encrypt(final Item data, final CryptType encryptType, final String secretKey, final String algorithm, @Nullable final String iv, @Nullable final String provider) throws XPathException {
        try {
            final String encrypted;
            if (data.getType() == Type.BASE64_BINARY || data.getType() == Type.HEX_BINARY) {
                final BinaryValue binaryValue = (BinaryValue) data;
                try (final InputStream is = binaryValue.getInputStream()) {
                    switch (encryptType) {
                        case SYMMETRIC:
                            encrypted = SymmetricEncryption.encrypt(is, secretKey, algorithm, iv, provider);
                            break;

                        case ASYMMETRIC:
                            encrypted = AsymmetricEncryption.encrypt(is, secretKey, algorithm);
                            break;

                        default:
                            //throw new XPathException(ErrorMessages.error_encType);
                            throw new XPathException(this, "Invalid encrypt type");
                    }
                }
            } else {
                switch (encryptType) {
                    case SYMMETRIC:
                        encrypted = SymmetricEncryption.encryptString(data.getStringValue(), secretKey, algorithm, iv, provider);
                        break;

                    case ASYMMETRIC:
                        encrypted = AsymmetricEncryption.encryptString(data.getStringValue(), secretKey, algorithm);
                        break;

                    default:
                        //throw new XPathException(ErrorMessages.error_encType);
                        throw new XPathException(this, "Invalid encrypt type");
                }
            }

            return new StringValue(encrypted);
        } catch (final CryptoException e) {
            throw new XPathException(this, e.getCryptoError().asMessage(), e);
        } catch (final IOException e) {
            throw new XPathException(this, e);
        }
    }

    private Sequence decrypt(final Item data, final CryptType decryptType, final String secretKey, final String algorithm, @Nullable final String iv, @Nullable final String provider) throws XPathException {
        try {
            final String decrypted;
            if (data.getType() == Type.BASE64_BINARY || data.getType() == Type.HEX_BINARY) {
                final BinaryValue binaryValue = (BinaryValue) data;
                try (final InputStream is = binaryValue.getInputStream()) {
                    switch (decryptType) {
                        case SYMMETRIC:
                            decrypted = SymmetricEncryption.decrypt(is, secretKey, algorithm, iv, provider);
                            break;

                        case ASYMMETRIC:
                            decrypted = AsymmetricEncryption.decrypt(is, secretKey, algorithm, iv, provider);
                            break;

                        default:
                            //throw new XPathException(ErrorMessages.error_decryptionType);
                            throw new XPathException(this, "Invalid encrypt type");
                    }
                }
            } else {
                switch (decryptType) {
                    case SYMMETRIC:
                        decrypted = SymmetricEncryption.decryptString(data.getStringValue(), secretKey, algorithm, iv, provider);
                        break;

                    case ASYMMETRIC:
                        decrypted = AsymmetricEncryption.decryptString(data.getStringValue(), secretKey, algorithm, iv, provider);
                        break;

                    default:
                        //throw new XPathException(ErrorMessages.error_decryptionType);
                        throw new XPathException(this, "Invalid encrypt type");
                }
            }

            return new StringValue(decrypted);
        } catch (final CryptoException e) {
            throw new XPathException(this, e.getCryptoError().asMessage(), e);
        } catch (final IOException e) {
            throw new XPathException(this, e);
        }
    }

    private enum CryptType {
        SYMMETRIC,
        ASYMMETRIC
    }
}
