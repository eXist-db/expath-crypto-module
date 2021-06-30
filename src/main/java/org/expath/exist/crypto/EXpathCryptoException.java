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
