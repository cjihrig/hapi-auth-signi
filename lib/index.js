'use strict';
const Crypto = require('crypto');
const Fs = require('fs');
const Boom = require('@hapi/boom');
const Package = require('../package.json');

const schemeDefaults = { authorizationType: 'signature' };


function register (server, options) {
  const settings = Object.assign({}, options);
  let tenants = settings.tenants;

  if (!Array.isArray(tenants)) {
    if (tenants !== null && typeof tenants === 'object') {
      tenants = [tenants];
    } else {
      throw new TypeError('tenants must be an object or array');
    }
  }

  // Use map() so user input is not changed.
  tenants = tenants.map((tenant, i) => {
    if (typeof tenant.secret !== 'string') {
      throw new TypeError(`tenants[${i}].secret must be a string`);
    }

    let key;

    if (typeof tenant.key === 'string' || Buffer.isBuffer(tenant.key)) {
      key = tenant.key;
    } else if (tenant.key !== undefined) {
      throw new TypeError(`tenants[${i}].key must be a string or Buffer`);
    }

    if (typeof tenant.path === 'string') {
      if (typeof key === 'string') {
        throw new Error(`tenants[${i}] specifies path and key`);
      }

      key = Fs.readFileSync(tenant.path);
    } else if (tenant.path !== undefined) {
      throw new TypeError(`tenants[${i}].path must be a string`);
    }

    if (key === undefined) {
      throw new Error(`tenants[${i}] missing path or key`);
    }

    if (typeof tenant.format !== 'string') {
      throw new TypeError(`tenants[${i}].format must be a string`);
    }

    if (typeof tenant.algorithm !== 'string') {
      throw new TypeError(`tenants[${i}].algorithm must be a string`);
    }

    return {
      secret: tenant.secret,
      key,
      format: tenant.format,
      algorithm: tenant.algorithm,
      authData: tenant.authData
    };
  });

  server.auth.scheme('signature', (server, options) => {
    const settings = Object.assign({}, schemeDefaults, options);
    const headerRegEx = new RegExp(`^${settings.authorizationType} (.+)$`, 'i');

    return {
      authenticate (request, h) {
        if (typeof request.headers.authorization !== 'string') {
          return h.unauthenticated(Boom.unauthorized());
        }

        const match = request.headers.authorization.match(headerRegEx);

        if (match === null) {
          return h.unauthenticated(Boom.unauthorized());
        }

        const signature = match[1];

        for (let i = 0; i < tenants.length; i++) {
          try {
            const tenant = tenants[i];
            const verify = Crypto.createVerify(tenant.algorithm);

            verify.update(tenant.secret);

            if (verify.verify(tenant.key, signature, tenant.format)) {
              return h.authenticated(tenant.authData);
            }
          } catch (err) {
            // Ignore error.
          }
        }

        return h.unauthenticated(Boom.unauthorized());
      }
    };
  });

  server.auth.strategy('signature', 'signature');
}

module.exports = {
  register,
  requirements: {
    hapi: '>=19.0.0'
  },
  pkg: Package
};
