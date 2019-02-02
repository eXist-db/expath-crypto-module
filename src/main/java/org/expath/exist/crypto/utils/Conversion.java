package org.expath.exist.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.annotation.Nullable;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.exist.util.io.FastByteArrayOutputStream;
import org.exist.xquery.XPathException;
import org.exist.xquery.value.BinaryValue;
import org.exist.xquery.value.IntegerValue;
import org.exist.xquery.value.NumericValue;
import org.exist.xquery.value.Sequence;
import org.exist.xquery.value.SequenceIterator;
import org.exist.xquery.value.Type;
import org.exist.xquery.value.ValueSequence;

import com.evolvedbinary.j8fu.Either;

import ro.kuberam.libs.java.crypto.utils.Buffer;

public class Conversion {

	private static Logger LOG = LogManager.getLogger(Conversion.class);

	@Nullable
	public static byte[] toByteArray(@Nullable final Either<InputStream, byte[]> data) throws IOException {
		if (data == null) {
			return null;
		}

		if (data.isRight()) {
			return data.right().get();
		} else {
			try (final InputStream is = data.left().get();
					final FastByteArrayOutputStream baos = new FastByteArrayOutputStream()) {

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
		LOG.debug("itemCount = {}", () -> itemCount);

			if (itemCount == 1) {
				final int itemType = sequence.itemAt(0).getType();
				LOG.debug("itemTypeName = {}", () -> Type.getTypeName(itemType));

				switch (itemType) {
				case Type.STRING:
				case Type.ELEMENT:
				case Type.DOCUMENT:
					final String itemStringValue = sequence.itemAt(0).getStringValue();
					LOG.debug("itemStringValue = {}, itemStringValue hash = {}, itemStringValue length = {}",
							() -> itemStringValue, () -> itemStringValue.hashCode(),
							() -> itemStringValue.trim().length());

					return Either.Right(itemStringValue.getBytes(StandardCharsets.UTF_8));

				case Type.BASE64_BINARY:
				case Type.HEX_BINARY:
					final BinaryValue binaryValue = (BinaryValue) sequence.itemAt(0);
					return Either.Left(binaryValue.getInputStream());

				default:
					return null;
				}
			} else {
				final FastByteArrayOutputStream baos = new FastByteArrayOutputStream();
				for (final SequenceIterator iterator = sequence.iterate(); iterator.hasNext();) {
					baos.write(((NumericValue) iterator.nextItem()).getInt());
				}
				return Either.Left(baos.toFastByteInputStream());
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
