 /*
  * Copyright 2017 Apigee Corporation.
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in
  * all copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  */
 // Load the http module to create an http server.
 var http = require("http");
 var apigee = require("apigee-access");
 var rs = require("jsrsasign");
 var jws = require("jws");
 var port = process.env.PORT || 10010;

 var err = {
     "error": "invalid_request",
     "error_description": "invalid request"
 };
 
var success = {
    "message": "assertion is valid"
}

function getPublicKey(publickeys, kid) {
    var key = "";
    if (publickeys.length == 1) return publickeys[0];
	for (i =0; i < publickeys.length; i++ ) {
		var t = publickeys[i];
		if(t[0] == kid) {
			key = t[1];
			break;
		}
	}
	return key;	
}


 var server = http.createServer(function(request, response) {

     var publicKeyResponse = apigee.getVariable(request, "publicKey");
     if (!publicKeyResponse) {
         publicKeyResponse = apigee.getVariable(request, "publicKeyResponse.content");
     }
     
     var publicKeyResponseObj = JSON.parse(publicKeyResponse);
     var assertion = apigee.getVariable(request,"assertion");

     try {
         if (request.url == "/token" && request.method == "POST") {
             var decode = jws.decode(assertion);
             if (!decode || !decode.header || !decode.header.kid) {
                 response.writeHead(500, {
                     "Content-Type": "application/json"
                 });
                 response.end(JSON.stringify(err));                 
             }
             var publickeys = publicKeyResponseObj.keys;
             var publicKey = getPublicKey(publickeys, decode.header.kid);
             if (!publicKey) {
                 response.writeHead(500, {
                     "Content-Type": "application/json"
                 });
                 response.end(JSON.stringify(err));                 
             }
             var key = rs.KEYUTIL.getKey(publicKey);
             var pem = rs.KEYUTIL.getPEM(key);
             //var result = rs.jws.JWS.verify(assertion, publicKey, ['RS256']);//
             var result = jws.verify(assertion, "RS256", pem); 
             if (result) {
              response.writeHead(200, {
                  "Content-Type": "application/json"
              });
              response.end(JSON.stringify(success));                          
             } else {
              response.writeHead(403, {
                  "Content-Type": "application/json"
              });
              response.end(JSON.stringify(err));              
             }
         } else {
             response.writeHead(404, {
                 "Content-Type": "application/json"
             });
             response.end(JSON.stringify(err));
         }
     } catch (error) {
         response.writeHead(500, {
             "Content-Type": "application/json"
         });
         response.end(JSON.stringify(error));
     }
 });

 server.listen(port);
