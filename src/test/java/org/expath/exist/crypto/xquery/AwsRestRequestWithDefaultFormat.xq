(:
 : eXist-db EXPath Cryptographic library
 : eXist-db wrapper for EXPath Cryptographic Java library
 : Copyright (C) 2016 Kuberam
 :
 : This library is free software; you can redistribute it and/or
 : modify it under the terms of the GNU Lesser General Public License
 : as published by the Free Software Foundation; either version 2.1
 : of the License, or (at your option) any later version.
 :
 : This library is distributed in the hope that it will be useful,
 : but WITHOUT ANY WARRANTY; without even the implied warranty of
 : MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 : GNU Lesser General Public License for more details.
 :
 : You should have received a copy of the GNU Lesser General Public License
 : along with this library; if not, write to the Free Software Foundation,
 : Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 :)
xquery version "3.0";

import module "http://expath.org/ns/crypto";

let $string-to-hash := 'PUT
c8fdb181845a4ca6b8fec737b3581d76
text/html
Thu, 17 Nov 2005 18:49:58 GMT
x-amz-magic:abracadabra
x-amz-meta-author:foo@bar.com
/quotes/nelson'
let $expected-result :=
	<expected-result>jZNOcbfWmD/A/f3hSvVzXZjM2HU=</expected-result>
let $private-key :='OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV'
let $actual-result :=
	<actual-result>
		{crypto:hmac($string-to-hash, $private-key, "HMAC-SHA-1")}
	</actual-result>
let $condition := normalize-space($expected-result/text()) = normalize-space($actual-result/text())
	

return
	<result>
		{
		(
		if ($condition)
			then <result-token>passed</result-token>
			else <result-token>failed</result-token>
		, $actual-result
		)
		}
	</result>