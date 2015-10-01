/*jslint node: true, nomen: true */
var request = require('request-json'),
  crypto = require('crypto'),
  querystring = require('query-string')

module.exports = function (customerId, secretKey) {
  'use strict';
  var client = request.createClient('https://rest.telesign.com/v1/');

  function generateAuthHeaders(customerId, secretKey, resource, method, contentType, authMethod, fields, cb) {
    var now = new Date(),
      currDate = now.toUTCString(),
      nonce = Math.random().toString(),
      stringToSign,
      signature,
      headers,
      AUTH_METHOD = {
        sha1: {hash: 'sha1', name: 'HMAC-SHA1'},
        sha256: {hash: 'sha256', name: 'HMAC-SHA256'}
      }

    if (!authMethod) {
      authMethod = 'sha1';
    }

    if (method === 'POST' || method === 'PUT') {
      contentType = 'application/x-www-form-urlencoded; charset=utf-8';
    } else{
      contentType = '';
    }

    stringToSign = method + '\n' +
      contentType + '\n' +
      '\n' +
      'x-ts-auth-method:' + AUTH_METHOD[authMethod].name + '\n' +
      'x-ts-date:' + currDate + '\n' +
      'x-ts-nonce:' + nonce;

    if (fields && (method === 'POST' || method === 'PUT')) {
      stringToSign += '\n' + querystring.stringify(fields);
    }

    stringToSign +=  '\n/v1/' + resource;
    signature = crypto.createHmac(AUTH_METHOD[authMethod].hash, new Buffer(secretKey, 'base64').toString('utf-8'));
    signature.write(stringToSign);
    signature.end(function () {
      var hash = signature.read();
      headers = {
        "Authorization": 'TSA ' + customerId + ':' + hash.toString('base64'),
        "x-ts-date": currDate.slice(0,-3),
        "x-ts-auth-method": AUTH_METHOD[authMethod].name,
        "x-ts-nonce": nonce
      }
      if(method === 'POST' || method ==='PUT'){
        headers['Content-length'] = querystring.stringify(fields).length;
      }
      return cb(null, headers);
    });
  }

  function randomWithNDigits(n) {
    return Math.round(Math.random() * Math.pow(10, n));
  }

  // A phone number beginning by '+' is still a valid phone number, but
  // Tele Sign API requires that phone numbers requires that phone numbers does
  // not begin with '+'. This function removes it, if present.
  function cleanPhoneNumber(phoneNumber) {
    if (typeof phoneNumber === 'string' && phoneNumber[0] === '+') {
      phoneNumber = phoneNumber.substring(1, phoneNumber.length );
    }
    return phoneNumber;
  }
  return {
    sms: function (phoneNumber, verifyCode, language, template, callback) {
      var resource = 'verify/sms',
        method = 'POST',
        headers,
        fields;
      phoneNumber = cleanPhoneNumber(phoneNumber);
      if (!verifyCode) {
        verifyCode = randomWithNDigits(5);
      }
      if (!language) {
        language = 'en';
      }

      if (!template) {
        template = '';
      }
      fields = {
        phone_number: phoneNumber,
        language: language,
        verify_code: verifyCode,
        template: template
      };

      headers = generateAuthHeaders(
        customerId,
        secretKey,
        resource,
        method,
        null,
        null,
        fields
      );

      client.post(resource, null, {headers: headers}, callback, true).form(fields);
    },

    verify: function (referenceId, callback) {
      var resource = 'verify/' + referenceId,
          method = 'GET',
          headers,
          fields = {};

      headers = generateAuthHeaders(
        customerId,
        secretKey,
        resource,
        method,
        null,
        null
      );
      for(var prop in headers){
        client.headers[prop] = headers[prop];
      }
      client.get(resource, callback, true).form(fields);
    },

    phoneId: {
      score: function(phoneNum, useCase, callback){
        var resource = 'phoneid/score/' + phoneNum,
            method = 'GET',
            headers,
            fields = {
              ucid: useCase
            },
            headers = generateAuthHeaders(
              customerId,
              secretKey,
              resource,
              method,
              null,
              null,
              fields,
              function(err, result){
                for(var prop in result){
                  client.headers[prop] = result[prop];
                }
                client.get(resource, callback).form(fields);
              }
            );

      },
      standard: function(phoneNum, useCase, callback){
        var resource = 'phoneid/standard/' + phoneNum,
            method = 'GET',
            headers,
            fields = {
              ucid: useCase
            },
            headers = generateAuthHeaders(
              customerId,
              secretKey,
              resource,
              method,
              null,
              null,
              fields,
              function(err, result){
                for(var prop in result){
                  client.headers[prop] = result[prop];
                }
                client.get(resource, callback).form(fields);
              }
          );
      }
    }
  };
}
