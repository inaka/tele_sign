/*jslint node: true, nomen: true */
var request = require('request-json'),
  crypto = require('crypto'),
  querystring = require('querystring');

module.exports = function (customerId, secretKey) {
  'use strict';
  var client = request.newClient('https://rest.telesign.com/');

  function generateAuthHeaders(customerId, secretKey, resource, method, contentType, authMethod, fields) {
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
    }

    stringToSign = method + '\n' + contentType +
      '\n\nx-ts-auth-method:' + AUTH_METHOD[authMethod].name +
      '\nx-ts-date:' + currDate +
      '\nx-ts-nonce:' + nonce;

    if (fields) {
      stringToSign += '\n' + querystring.stringify(fields);
    }

    stringToSign +=  '\n' + resource;
    signature = new Buffer(
      crypto.createHmac(
        AUTH_METHOD[authMethod].hash,
        new Buffer(secretKey, 'base64')
      ).update(stringToSign).digest()
    ).toString('base64');

    headers = {
      "Authorization": 'TSA ' + customerId + ':' + signature,
      "x-ts-date": currDate,
      "x-ts-auth-method": AUTH_METHOD[authMethod].name,
      "x-ts-nonce": nonce,
      "Content-length": querystring.stringify(fields).length
    }
    return headers;
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
  this.sms = function (phoneNumber, verifyCode, language, template, callback) {
    var resource = '/v1/verify/sms',
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
      verify_code: verifyCode
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

    client.post(resource, null, {headers: headers}, callback, false).form(fields);
  };
}
