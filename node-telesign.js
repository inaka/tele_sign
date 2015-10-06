var request     = require('request');
var util        = require('util');
var crypto      = require('crypto');
var querystring = require('query-string');
var NEWLINE     = require('os').EOL;
var q           = require('q');
var URLSafeBase64 = require('urlsafe-base64');

function teleSign(customerId, secret, authMethod, apiUrl, timeout){
  var parent       = this;
  this.authMethod  = (authMethod) ? authMethod : 'sha1';
  this.timeout     = (timeout) ? timeout : 5;
  this.baseUrl     = (apiUrl) ? apiUrl : 'https://rest.telesign.com/';
  this.baseRequest = request.defaults({baseUrl: this.baseUrl});
  this.secretKey   = secret;
  this.customer    = customerId;
  return {
    phoneId:{
      score: function(phoneNum, useCaseCode, callback){
        var self       = this;
        var deferred   = q.defer();
        var resource   = 'v1/phoneid/score/'+phoneNum;
        var method     = 'GET';
        if(!useCaseCode) useCaseCode = 'UNKN';

        parent.createHeaders(resource, method).then(function(headers){
          request.get({
            baseUrl: parent.baseUrl,
            url: resource,
            headers: headers,
            qs: {ucid: useCaseCode}
          },
          function(err, resp){
            if(err) return deferred.reject(err);
            return deferred.resolve(resp.body);
          });
        });
        return deferred.promise;
      }
    }
  }
}

teleSign.prototype.AUTH_METHODS = {
  sha1: {hash: 'sha1', name: 'HMAC-SHA1'},
  sha256: {hash: 'sha256', name: 'HMAC-SHA256'}
};

teleSign.prototype.getCurrTime = function(){
  this.currTime = new Date().toUTCString().slice(0,-3)+'+0000';
  return this.currTime;
};

teleSign.prototype.createNonce = function(){
  var deferred = q.defer();
  var self = this;
  crypto.randomBytes(48, function(err, buf) {
    if(err) return deferred.reject(err);
    self.nonce = buf.toString('hex');
    return deferred.resolve(self.nonce);
  });
  return deferred.promise;
};

teleSign.prototype.createAuthHeader = function(resource, method){
  var deferred     = q.defer();
  var self         = this;
  var parent       = teleSign.prototype;
  var stringToSign = '';
  var contentType  = '';

  if(method === 'POST' || this.method === 'PUT') {
    contentType = 'application/x-www-form-urlencoded; charset=utf-8';
  } else{
    contentType = '';
  }

  this.createNonce().then(function(nonceData){
    var stringToSign = method + NEWLINE +
      contentType + NEWLINE +
      NEWLINE +
      'x-ts-auth-method:' + parent.AUTH_METHODS[self.authMethod].name + NEWLINE +
      'x-ts-date:' + parent.getCurrTime() + NEWLINE +
      'x-ts-nonce:' + nonceData;
    if (self.fields && (method === 'POST' || method === 'PUT')){
      stringToSign += NEWLINE + querystring.stringify(self.fields);
    }
    stringToSign +=  NEWLINE + '/v1/' + resource;
    var signature = crypto.createHmac(teleSign.prototype.AUTH_METHODS[self.authMethod].hash, URLSafeBase64(self.secretKey).toString('utf-8'));
    signature = signature.update(stringToSign).digest('base64');
    return deferred.resolve('TSA ' + self.customer + ':' + signature);

  });
  return deferred.promise;
};

teleSign.prototype.createHeaders = function(resource, method){
  var deferred = q.defer();
  var self = this;
  this.createAuthHeader(resource, method).then(function(signedData){
    var headers = {
      "Authorization": signedData,
      "x-ts-date": self.currTime,
      "x-ts-auth-method": teleSign.prototype.AUTH_METHODS[self.authMethod].name,
      "x-ts-nonce": self.nonce
    }
    if(method === 'POST' || method ==='PUT'){
      headers['Content-length'] = querystring.stringify(this.fields).length;
    }
    return deferred.resolve(headers);
  });
  return deferred.promise;
};

module.exports = teleSign;
