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
package org.expath.exist.crypto.digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import com.evolvedbinary.j8fu.Either;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.xquery.BasicFunction;
import org.exist.xquery.FunctionSignature;
import org.exist.xquery.XPathException;
import org.exist.xquery.XQueryContext;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.FunctionParameterSequenceType;
import org.exist.xquery.value.IntegerValue;
import org.exist.xquery.value.NumericValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.SequenceIterator;
import org.exist.xquery.value.StringValue;
import org.exist.xquery.value.Type;
import org.exist.xquery.value.ValueSequence;

import ro.kuberam.libs.java.crypto.digest.Hmac;

import javax.annotation.Nullable;

import static org.exist.xquery.FunctionDSL.*;
import static org.expath.exist.crypto.ExistExpathCryptoModule.*;

public class HmacFunction extends BasicFunction {

    private static final Logger LOG = LogManager.getLogger(HmacFunction.class);

    private static final String FS_HMAC_NAME = "hmac";
    private static final FunctionParameterSequenceType FS_HMAC_PARAM_DATA = optManyParam("data", Type.ATOMIC, "The data to be authenticated. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
    private static final FunctionParameterSequenceType FS_HMAC_PARAM_KEY = optManyParam("key", Type.ATOMIC, "The secret key used for calculating the authentication code. This parameter can be of type xs:string, xs:byte*, xs:base64Binary, or xs:hexBinary.");
    private static final FunctionParameterSequenceType FS_HMAC_PARAM_ALGORITHM = param("algorithm", Type.STRING, "The cryptographic hashing algorithm.");

    public final static FunctionSignature FS_HMAC[] = functionSignatures(
        FS_HMAC_NAME,
        "Hashes the input message.",
        returnsOptMany(Type.BYTE),
        arities(
            arity(
                FS_HMAC_PARAM_DATA,
                FS_HMAC_PARAM_KEY,
                FS_HMAC_PARAM_ALGORITHM
            ),
            arity(
                FS_HMAC_PARAM_DATA,
                FS_HMAC_PARAM_KEY,
                FS_HMAC_PARAM_ALGORITHM,
                param("encoding", Type.STRING, "The encoding of the output. The legal values are \"hex\" and \"base64\". The result is generated accordingly as xs:base64Binary string or xs:hexBinary string.")
            )
        )
    );

    public HmacFunction(final XQueryContext context, final FunctionSignature signature) {
        super(context, signature);
    }

    @Override
    public Sequence eval(final Sequence[] args, final Sequence contextSequence) throws XPathException {
        final int argsLength = args.length;

        if(LOG.isDebugEnabled()) {
            LOG.debug("argsLength = " + argsLength);
            LOG.debug("data item count = " + args[0].getItemCount());
        }

        final Sequence result;
        Either<InputStream, byte[]> data = null;
        boolean dataStreamClosed = false;
        try {
            data = sequence2javaTypes(args[0]);

            if(LOG.isDebugEnabled()) {
                LOG.debug("secretKey item count = " + args[1].getItemCount());
            }

            final byte[] secretKey = toByteArray(sequence2javaTypes(args[1]));
            if(LOG.isDebugEnabled()) {
                LOG.debug("secretKey item count = " + args[1].getItemCount());
            }

            final String algorithm = args[2].getStringValue();
            if(LOG.isDebugEnabled()) {
                LOG.debug("algorithm = " + algorithm);
            }

            String encoding = "base64";
            if (args.length == 4) {
                encoding = args[3].getStringValue();
            }
            if(LOG.isDebugEnabled()) {
                LOG.debug("encoding = " + encoding);
            }

            if (argsLength == 3) {
                final byte[] resultBytes;
                if(data.isLeft()) {
                    try(final InputStream is = data.left().get()) {
                        resultBytes = Hmac.hmac(is, secretKey, algorithm);
                    }
                    dataStreamClosed = true;
                } else {
                    resultBytes =  Hmac.hmac(data.right().get(), secretKey, algorithm);
                }
                final int resultBytesLength = resultBytes.length;

                if(LOG.isDebugEnabled()) {
                    LOG.debug("resultBytesLength = " + resultBytesLength);
                    LOG.debug("resultBytes = " + Arrays.toString(resultBytes));
                }

                result = new ValueSequence();
                for (int i = 0, il = resultBytesLength; i < il; i++) {
                    result.add(new IntegerValue(resultBytes[i]));
                }
            } else if (argsLength == 4) {
                final String resultString;

                if(data.isLeft()) {
                    try(final InputStream is = data.left().get()) {
                        resultString = Hmac.hmac(is, secretKey, algorithm, encoding);
                    }
                } else {
                    resultString = Hmac.hmac(data.right().get(), secretKey, algorithm, encoding);
                }

                if(LOG.isDebugEnabled()) {
                    LOG.debug("resultString = " + resultString);
                }

                result = new StringValue(resultString);
            } else {
                result = Sequence.EMPTY_SEQUENCE;
            }
        } catch (final Exception ex) {
            throw new XPathException(ex.getMessage());
        } finally {
            if (data != null && data.isLeft() && !dataStreamClosed) {
                try {
                    data.left().get().close();
                } catch (final IOException e) {
                    throw new XPathException(e.getMessage());
                }
            }
        }

        return result;
    }

    private @Nullable Either<InputStream, byte[]> sequence2javaTypes(final Sequence sequence) throws XPathException {
        final int itemCount = sequence.getItemCount();
        if(LOG.isDebugEnabled()) {
            LOG.debug("itemCount = " + itemCount);
        }

        try {
            if (itemCount == 1) {
                final int itemType = sequence.itemAt(0).getType();
                if(LOG.isDebugEnabled()) {
                    LOG.debug("itemTypeName = " + Type.getTypeName(itemType));
                }

                switch (itemType) {
                    case Type.STRING:
                    case Type.ELEMENT:
                    case Type.DOCUMENT:
                        final String itemStringValue = sequence.itemAt(0).getStringValue();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("itemStringValue = " + itemStringValue);
                            LOG.debug("itemStringValue hash = " + itemStringValue.hashCode());
                            LOG.debug("itemStringValue length = " + itemStringValue.trim().length());
                        }

                        return Either.Right(itemStringValue.getBytes(StandardCharsets.UTF_8));

                    case Type.BASE64_BINARY:
                    case Type.HEX_BINARY:
                        final BinaryValue binaryValue = (BinaryValue) sequence.itemAt(0);
                        return Either.Left(binaryValue.getInputStream());

                    default:
                        return null;
                }
            } else {
                try(final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    for (final SequenceIterator iterator = sequence.iterate(); iterator.hasNext(); ) {
                        baos.write(((NumericValue) iterator.nextItem()).getInt());
                    }
                    return Either.Right(baos.toByteArray());
                }
            }
        } catch (final Exception ex) {
            throw new XPathException(ex.getMessage());
        }
    }

    private @Nullable byte[] toByteArray(@Nullable final Either<InputStream, byte[]> data) throws IOException {
        if(data == null) {
            return null;
        }

        if(data.isRight()) {
            return data.right().get();
        } else {
            try(final InputStream is = data.left().get();
                    final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                final byte[] buf = new byte[1024];
                int read = -1;
                while((read = is.read(buf)) > -1) {
                    baos.write(buf, 0, read);
                }

                return baos.toByteArray();
            }
        }
    }

    private byte[] binaryValueToByte(final BinaryValue binary) throws XPathException {
        try(final ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            binary.streamBinaryTo(os);
            return os.toByteArray();
        } catch (final IOException ioe) {
            throw new XPathException(this, ioe);
        }
    }
}
