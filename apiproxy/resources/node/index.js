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

 var server = http.createServer(function(request, response) {

     var publicKey = apigee.getVariable(request, "private.publicKey");
     var assertion = apigee.getVariable(request,"assertion");

     try {
      console.log(request.url);
         if (request.url == "/token" && request.method == "POST") {
             var result = jws.verify(assertion, "RS256", publicKey); 
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
