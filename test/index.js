'use strict';
const Crypto = require('crypto');
const Fs = require('fs');
const Path = require('path');
const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');
const Auth = require('../lib');

// Test shortcuts
const lab = exports.lab = Lab.script();
const { describe, it } = lab;
const { expect } = Code;

const fixturesDir = Path.join(__dirname, 'fixtures');


describe('Hapi Auth Signature', () => {
  it('authenticates properly', async () => {
    const server = await getServer();
    const res = await server.inject({
      method: 'GET',
      url: '/foo',
      headers: { Authorization: `Signature ${getSignature()}` }
    });

    expect(res.statusCode).to.equal(200);
    expect(JSON.parse(res.payload)).to.equal({
      isAuthenticated: true,
      isAuthorized: false,
      credentials: { username: 'peterpluck' },
      strategy: 'signature',
      mode: 'required',
      error: null
    });
  });

  it('authenticates properly with key as string', async () => {
    const server = await getServer({
      tenants: {
        secret: 'foo',
        key: Fs.readFileSync(Path.join(fixturesDir, 'public.pem')).toString(),
        algorithm: 'sha256',
        format: 'base64',
        authData: { credentials: { username: 'peterpluck' } }
      }
    });
    const res = await server.inject({
      method: 'GET',
      url: '/foo',
      headers: { Authorization: `Signature ${getSignature()}` }
    });

    expect(res.statusCode).to.equal(200);
    expect(JSON.parse(res.payload)).to.equal({
      isAuthenticated: true,
      isAuthorized: false,
      credentials: { username: 'peterpluck' },
      strategy: 'signature',
      mode: 'required',
      error: null
    });
  });

  it('authenticates properly with key as buffer', async () => {
    const server = await getServer({
      tenants: {
        secret: 'foo',
        key: Fs.readFileSync(Path.join(fixturesDir, 'public.pem')),
        algorithm: 'sha256',
        format: 'base64',
        authData: { credentials: { username: 'peterpluck' } }
      }
    });
    const res = await server.inject({
      method: 'GET',
      url: '/foo',
      headers: { Authorization: `Signature ${getSignature()}` }
    });

    expect(res.statusCode).to.equal(200);
    expect(JSON.parse(res.payload)).to.equal({
      isAuthenticated: true,
      isAuthorized: false,
      credentials: { username: 'peterpluck' },
      strategy: 'signature',
      mode: 'required',
      error: null
    });
  });

  it('does not authenticate without authorization header', async () => {
    const server = await getServer();
    const res = await server.inject({
      method: 'GET',
      url: '/foo'
    });

    expect(res.statusCode).to.equal(401);
  });

  it('does not authenticate with malformed authorization header', async () => {
    const server = await getServer();
    const res = await server.inject({
      method: 'GET',
      url: '/foo',
      headers: { Authorization: `${getSignature()}` }
    });

    expect(res.statusCode).to.equal(401);
  });

  it('does not authenticate with bad signature', async () => {
    const server = await getServer();
    const res = await server.inject({
      method: 'GET',
      url: '/foo',
      headers: { Authorization: `Signature x${getSignature()}` }
    });

    expect(res.statusCode).to.equal(401);
  });

  it('throws on bad input', () => {
    async function fail (options) { // eslint-disable-line require-await
      expect(async () => {
        await getServer(options);
      }).to.throw();
    }

    fail({ tenants: 'foo' });
    fail({ tenants: null });
    fail({ tenants: { secret: 5 } });
    fail({ tenants: { secret: 'foo' } });
    fail({ tenants: { secret: 'foo', key: 5 } });
    fail({ tenants: { secret: 'foo', path: 5 } });
    fail({ tenants: { secret: 'foo', key: 'bar', path: 'baz' } });
    fail({ tenants: { secret: 'foo', key: 'bar', format: 5 } });
    fail({ tenants: { secret: 'foo', key: 'bar', format: 'qux', algorithm: 5 } });
  });
});


async function getServer (options) {
  const server = Hapi.server();
  const settings = Object.assign({
    tenants: [
      {
        secret: 'foo',
        path: Path.join(fixturesDir, 'public.pem'),
        algorithm: 'sha256',
        format: 'base64',
        authData: { credentials: { username: 'peterpluck' } }
      }
    ]
  }, options);

  await server.register({
    plugin: Auth,
    options: settings
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

  return server;
}


function getSignature (options) {
  const settings = Object.assign({
    path: Path.join(fixturesDir, 'private.pem'),
    algorithm: 'sha256',
    format: 'base64'
  }, options);
  const privateKey = Fs.readFileSync(settings.path);
  const signer = Crypto.createSign(settings.algorithm);

  signer.update('foo');
  return signer.sign(privateKey, settings.format);
}
