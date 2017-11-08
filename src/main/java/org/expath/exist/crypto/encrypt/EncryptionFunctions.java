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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.Type;
import org.exist.xquery.value.StringValue;

import ro.kuberam.libs.java.crypto.ErrorMessages;
import ro.kuberam.libs.java.crypto.encrypt.AsymmetricEncryption;
import ro.kuberam.libs.java.crypto.encrypt.SymmetricEncryption;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

/**
 * @author Claudius Teodorescu <claudius.teodorescu@gmail.com>
 */

public class EncryptionFunctions extends BasicFunction {

    private static final Logger LOG = LogManager.getLogger(EncryptionFunctions.class);

    private static final String FS_ENCRYPT_NAME = "encrypt";
    private static final String FS_DECRYPT_NAME = "decrypt";
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_DATA = param("data", Type.ATOMIC, "The data to be encrypted or decrypted. This parameter can be of type xs:string, xs:base64Binary, or xs:hexBinary.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_SECRET_KEY = param("secret-key", Type.STRING, "The secret key used for encryption or decryption, as string.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_CRYPTOGRAPHIC_ALGORITHM = param("secret-key", Type.STRING, "The cryptographic algorithm used for encryption or decryption.");
    private static final FunctionParameterSequenceType FS_ENCRYPT_PARAM_IV = optParam("secret-key", Type.STRING, "The initialization vector.");
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
        String result = null;
        final String functionName = getSignature().getName().getLocalPart();

        try {
            if ("encrypt".equals(functionName)) {
                if ("symmetric".equals(args[1].getStringValue())) {
                    result = SymmetricEncryption.encryptString(args[0].getStringValue(),
                            args[2].getStringValue(), args[3].getStringValue(), args[4].getStringValue(),
                            args[5].getStringValue());
                } else if ("asymmetric".equals(args[1].getStringValue())) {
                    result = AsymmetricEncryption.encryptString(args[0].getStringValue(),
                            args[2].getStringValue(), args[3].getStringValue());
                } else {
                    throw new XPathException(ErrorMessages.error_encType);
                }
            } else if ("decrypt".equals(functionName)) {
                if ("symmetric".equals(args[1].getStringValue())) {
                    result = SymmetricEncryption.decryptString(args[0].getStringValue(),
                            args[2].getStringValue(), args[3].getStringValue(), args[4].getStringValue(),
                            args[5].getStringValue());
                } else if ("asymmetric".equals(args[1].getStringValue())) {

                } else {
                    throw new XPathException(ErrorMessages.error_decryptionType);
                }
            }
        } catch (final Exception ex) {
            throw new XPathException(ex.getMessage());
        }

        return new StringValue(result);
    }
}
