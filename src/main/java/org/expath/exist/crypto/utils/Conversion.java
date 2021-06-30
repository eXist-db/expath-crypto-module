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
package org.expath.exist.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.annotation.Nullable;

import org.exist.xquery.XPathException;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.IntegerValue;
import org.exist.xquery.value.NumericValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.SequenceIterator;
import org.exist.xquery.value.Type;
import org.exist.xquery.value.ValueSequence;

import org.apache.commons.io.output.UnsynchronizedByteArrayOutputStream;

import com.evolvedbinary.j8fu.Either;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ro.kuberam.libs.java.crypto.utils.Buffer;

public class Conversion {

	private static final Logger LOG = LoggerFactory.getLogger(Conversion.class);

	@Nullable
	public static byte[] toByteArray(@Nullable final Either<InputStream, byte[]> data) throws IOException {
		if (data == null) {
			return null;
		}

		if (data.isRight()) {
			return data.right().get();
		} else {
			try (final InputStream is = data.left().get();
					final UnsynchronizedByteArrayOutputStream baos = new UnsynchronizedByteArrayOutputStream()) {

				final byte[] buf = new byte[Buffer.TRANSFER_SIZE];
				int read = -1;
				while ((read = is.read(buf)) > -1) {
					baos.write(buf, 0, read);
				}

				return baos.toByteArray();
			}
		}
	}

	@Nullable
	public static Either<InputStream, byte[]> sequence2javaTypes(final Sequence sequence) throws XPathException {
		final int itemCount = sequence.getItemCount();
		LOG.debug("itemCount = {}", itemCount);

		if (itemCount == 1) {
			final int itemType = sequence.itemAt(0).getType();
			LOG.debug("itemTypeName = {}", Type.getTypeName(itemType));

			switch (itemType) {
			case Type.STRING:
			case Type.ELEMENT:
			case Type.DOCUMENT:
				final String itemStringValue = sequence.itemAt(0).getStringValue();
				LOG.debug("itemStringValue = {}, itemStringValue length = {}", itemStringValue,
						itemStringValue.trim().length());

				return Either.Right(itemStringValue.getBytes(StandardCharsets.UTF_8));

			case Type.BASE64_BINARY:
			case Type.HEX_BINARY:
				final BinaryValue binaryValue = (BinaryValue) sequence.itemAt(0);
				return Either.Left(binaryValue.getInputStream());

			default:
				return null;
			}
		} else {
			final UnsynchronizedByteArrayOutputStream baos = new UnsynchronizedByteArrayOutputStream();
			for (final SequenceIterator iterator = sequence.iterate(); iterator.hasNext();) {
				baos.write(((NumericValue) iterator.nextItem()).getInt());
			}
			return Either.Left(baos.toInputStream());
		}
	}

	public static Sequence byteArrayToIntegerSequence(byte[] bytes) {
		Sequence result = new ValueSequence();
		int bytesLength = bytes.length;

		for (int i = 0, il = bytesLength; i < il; i++) {
			try {
				result.add(new IntegerValue(bytes[i]));
			} catch (XPathException e) {
				e.printStackTrace();
			}
		}

		return result;
	}
}
