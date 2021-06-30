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

import org.exist.dom.QName;
import org.exist.xquery.ErrorCodes.ErrorCode;

import ro.kuberam.libs.java.crypto.CryptoError;

public class ExpathCryptoErrorCode extends ErrorCode {
	public ExpathCryptoErrorCode(String code, String description) {
		super(new QName(code, ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX), description);
	}

	public ExpathCryptoErrorCode(CryptoError cryptoError) {
		super(new QName(cryptoError.getCode(), ExistExpathCryptoModule.NAMESPACE_URI, ExistExpathCryptoModule.PREFIX), cryptoError.getDescription());
	}
}
