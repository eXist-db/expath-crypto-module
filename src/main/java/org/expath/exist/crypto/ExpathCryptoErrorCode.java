package org.expath.exist.crypto;

import org.exist.dom.QName;
import org.exist.xquery.ErrorCodes.ErrorCode;

import ro.kuberam.libs.java.crypto.CryptoError;

import java.lang.reflect.Field;

public class ExpathCryptoErrorCode extends ErrorCode {
	public ExpathCryptoErrorCode(String code, String description) {
		super(new QName(code, ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX), description);
	}

	public ExpathCryptoErrorCode(CryptoError cryptoError) {
		super(new QName(cryptoError.name(), ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX), getDescription(cryptoError));
	}

	public static String getDescription(final CryptoError cryptoError) {
		try {
			final Field field = cryptoError.getClass().getDeclaredField("description");
			field.setAccessible(true);
			return (String) field.get(cryptoError);
		} catch (final  NoSuchFieldException | IllegalAccessException e) {
			return "UNKNOWN";
		}
	}
}
