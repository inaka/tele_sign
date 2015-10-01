var request     = require('request');
var util        = require('util');
var crypto      = require('crypto');
var querystring = require('query-string');
var NEWLINE     = require('os').EOL;
var q           = require('q')

module.exports = teleSign;

function teleSign(customerId, secret, authMethod, apiUrl, timeout){
  var AUTH_METHODS = {
    sha1: {hash: 'sha1', name: 'HMAC-SHA1'},
    sha256: {hash: 'sha256', name: 'HMAC-SHA256'}
  };
  this.authMethod = (!authMethod) ? 'sha1' : authMethod;
  this.timeout = (!timeout) ? 5 : timeout;
  this.baseUrl = (!apiUrl) ? 'https://rest.telesign.com/' : apiUrl;
  this.baseRequest = request.defaults({
    baseUrl: this.baseUrl
  });
  return {
    phoneId:{
      score: function(phoneNum, useCaseCode, cb){
        util.inherits(this, main);
        var self = this;
        var deferred = q.defer();
        if(!useCaseCode) useCaseCode = 'UNKN';
        this.method = 'GET';
        this.resource = 'v1/phoneid/score/'+phoneNum;
        this.createHeaders().then(function(headers){
          var scoreReq = this.baseRequest.get({
            url: this.resource,
            headers: headers,
            qs: {ucid: useCaseCode}
          }, function(err, resp){
            if(err) return deferred.reject(err);
            return deferred.resolve(resp.body);
          });
        })
        return deferred.promise.nodeify(callback)
      }
    }
  }
}


teleSign.prototype.getCurrTime = function(){
  this.currTime = new Date().toUTCString().slice(0,-3)+'+0000';
  return this.currTime;
}

teleSign.prototype.createNonce = function(){
  var deferred = q.defer();
  crypto.randomBytes(48, function(err, buf) {
    if(err) return deferred.reject(err);
    this.nonce = buf.toString('hex');
    return deferred.resolve(buf.toString('hex'));
  });
}

teleSign.prototype.createAuthHeader = function(){
  var deferred = q.defer();
  var stringToSign = '';
  if(this.method === 'POST' || this.method === 'PUT') {
    contentType = 'application/x-www-form-urlencoded; charset=utf-8';
  } else{
    contentType = 'text/plain';
  }
  this.createNonce().then(function(nonceData){
    stringToSign += method + NEWLINE +
      contentType + NEWLINE +
      NEWLINE +
      'x-ts-auth-method:' + AUTH_METHODS[this.authMethod].name + NEWLINE +
      'x-ts-date:' + this.getcurrTime() + NEWLINE +
      'x-ts-nonce:' + nonceData;

    if (this.fields && (this.method === 'POST' || this.method === 'PUT')){
      stringToSign += NEWLINE + querystring.stringify(this.fields);
    }
    stringToSign +=  NEWLINE + '/v1/' + this.resource;
    signature = crypto.createHmac(AUTH_METHOD[this.authMethod].hash, new Buffer(secretKey, 'base64').toString('utf-8'));
    signature.write(stringToSign);
    signature.end(function(){
      var hash = signature.read();
      return deferred.resolve('TSA ' + customerId + ':' + hash.toString('base64'));
    });
  });
}

teleSign.prototype.createHeaders = function(){
  var deferred = q.defer();
  var auth = this.createAuthHeader().then(function(signedData){
    var headers = {
      "Authorization": signedData,
      "x-ts-date": this.currTime,
      "x-ts-auth-method": AUTH_METHOD[this.authMethod].name,
      "x-ts-nonce": this.nonce
    }
    if(this.method === 'POST' || this.method ==='PUT'){
      headers['Content-length'] = querystring.stringify(this.fields).length;
    }
    return deferred.resolve(headers);
  })
}
