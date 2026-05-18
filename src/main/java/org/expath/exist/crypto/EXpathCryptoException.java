/*
 * SPDX LGPL-2.1-or-later
 * Copyright (C) 2016 Claudius Teodorescu
 */
package org.expath.exist.crypto;

import org.exist.xquery.ErrorCodes.ErrorCode;
import org.exist.xquery.Expression;
import org.exist.xquery.XPathException;

import ro.kuberam.libs.java.crypto.CryptoError;

public class EXpathCryptoException extends XPathException {

	private static final long serialVersionUID = -6789727720893604433L;
	
	public EXpathCryptoException(Expression expr, CryptoError cryptoError) {
		super(expr, new ExpathCryptoErrorCode(cryptoError), cryptoError.getDescription());
	}

	public EXpathCryptoException(Expression expr, Exception exception) {
		super(expr, new ExpathCryptoErrorCode(exception.getClass().getCanonicalName(), exception.toString()),
				exception.toString());
	}

	public EXpathCryptoException(Expression expr, ErrorCode errorCode, String description) {
		super(expr, errorCode, description);
	}
}
