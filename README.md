# hapi-auth-signi

[![Current Version](https://img.shields.io/npm/v/hapi-auth-signi.svg)](https://www.npmjs.org/package/hapi-auth-signi)
[![Build Status via Travis CI](https://travis-ci.org/cjihrig/hapi-auth-signi.svg?branch=master)](https://travis-ci.org/cjihrig/hapi-auth-signi)
![Dependencies](http://img.shields.io/david/cjihrig/hapi-auth-signi.svg)
[![belly-button-style](https://img.shields.io/badge/eslint-bellybutton-4B32C3.svg)](https://github.com/cjihrig/belly-button)

hapi authentication scheme for validating signed requests. Note that this plugin is not a substitute for a full blown production auth service.

## Basic Usage

```javascript
'use strict';
const Hapi = require('hapi');
const HapiAuthSignature = require('hapi-auth-signi');
const server = Hapi.server();

await server.register({
  plugin: HapiAuthSignature,
  options: {
    tenants: [
      {
        secret: 'foo',
        path: './public.pem',
        algorithm: 'sha256',
        format: 'base64',
        authData: { credentials: { username: 'peterpluck' } }
      }
    ]
  }
});

server.route([
  {
    method: 'GET',
    path: '/foo',
    config: {
      auth: 'signature',
      handler (request, h) {
        return request.auth;
      }
    }
  }
]);
```

## Signing Requests

`hapi-auth-signi` expects incoming requests to include an `'Authorization'` HTTP header of the following format:

```
Authorization: Signature signature
```

`signature` can be created using the following Node.js code:

```javascript
'use strict';
const Crypto = require('crypto');
const Fs = require('fs');
const privateKey = Fs.readFileSync('./path_to_private_key');
const signer = Crypto.createSign('sha256');

signer.update('secret');
const signature = signer.sign(privateKey, 'base64');
// signature is the value to include in your request
```

## API

`hapi-auth-signi` is a hapi plugin that exposes an authentication scheme named `'signature'`. An authentication strategy of the same name is also created. The plugin supports the following configuration options:

### `tenants`

An object or array of objects defining the supported clients. Each tenant adheres to the following schema.

- `secret` (string) - The text that the client is expected to sign.
- `key` (string or buffer) - The contents of a public key used to verify messages. Required if `path` is not specified. Cannot be used with `path`.
- `path` (string) - The path to a public key file used to verify messages. Required if `key` is not specified. Cannot be used with `key`.
- `algorithm` (string) - The algorithm name passed to `Crypto.createVerify()`.
- `format` (string) - The format of the signature passed to `Verify.verify()`.
- `authData` (object) - The result returned on successful authentication.

### Custom Strategies

The default strategy, `'signature'` uses the default settings described below. It is possible to create additional strategies by calling `server.auth.strategy('your_strategy_name_here', 'signature', options)` with customized options.

#### `authorizationType`

A string representing the authorization type. This is expected to be the first part of the `Authorization` HTTP header. Defaults to `'signature'`.
