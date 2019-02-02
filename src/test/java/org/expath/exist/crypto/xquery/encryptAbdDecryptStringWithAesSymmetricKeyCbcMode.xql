(:
 : eXist-db EXPath Cryptographic library
 : eXist-db wrapper for EXPath Cryptographic Java library
 : Copyright (C) 2016 Claudius Teodorescu
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
xquery version "3.1";

import module namespace crypto="http://expath.org/ns/crypto";

let $text := "String for tests. String for tests. String for tests."
let $type := 'symmetric'
let $key :=  '1234567890123456'
let $algorithm := 'AES/CBC/PKCS5Padding'
let $iv := crypto:hash("initialization vector", "MD5", "base64")

let $expected-result := $text
let $iv := crypto:hash("initialization vector", "MD5", "base64")
let $actual-result :=
	let $encrypted := crypto:encrypt($text, $type, $key, $algorithm, $iv, "SunJCE")
    let $decrypted := crypto:decrypt($encrypted, $type, $key, $algorithm, $iv, "SunJCE")				
    
    return $decrypted
let $condition := normalize-space($expected-result) = normalize-space($actual-result)
	

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
	