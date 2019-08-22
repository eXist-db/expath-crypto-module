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
		super(new QName(cryptoError.getCode(), ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX), cryptoError.getDescription());
	}
}
