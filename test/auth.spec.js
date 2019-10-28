const assert= require('assert');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const querystring = require('querystring');
const authHandler = require('../auth');

const port = 8080;

const privateKeyContent=fs.readFileSync('test/key.pem');
const privateKeySha256=crypto.createHash("SHA256").update(privateKeyContent.toString()).digest().toString();

const encrypt=(text)=>{
  return b64urlEncode(crypto.privateEncrypt(crypto.createPrivateKey(privateKeyContent),Buffer.from(text)));
};

/**
 * @param {string} data
 * @returns {string}
 */
const b64urlDecode=(data)=>{
  return Buffer.from(data.
      replace(/[-]/g,'+').
      replace(/[_]/g,'/'),
    'base64').toString();
};

/**
 * @param {Buffer} data
 * @returns {string}
 */
const b64urlEncode=(data)=>{
  return data.toString('base64').
    replace(/[+]/g,'-').
    replace(/[/]/g,'_').
    replace(/[=]+$/,'');
};

/**
 * @param {string} jwt
 * @returns {{username:string,data:Object<string,*>}}
 */
const jwtDecode=(jwt)=>{
  const i = jwt.indexOf('.');
  assert.notStrictEqual(i, -1);
  const j = jwt.indexOf('.', i+1);
  assert.notStrictEqual(j, -1);
  const header = JSON.parse(b64urlDecode(jwt.substring(0,i)));
  assert.strictEqual(header.alg, 'HS256');
  assert.strictEqual(header.typ, 'jwt');
  const payload = JSON.parse(b64urlDecode(jwt.substring(i+1,j)));
  const signature = jwt.substring(j+1);
  const hmac=crypto.createHmac('SHA256',privateKeySha256);
  assert.strictEqual(b64urlEncode(hmac.update(jwt.substring(0,j)).digest()), signature);
  return payload;
};

const sha256b64=(text)=>{
  return crypto.createHash('sha256').update(text).digest('base64').
    replace('+','-').replace('/','_').replace('=','');
};

const delay=(millis)=>new Promise(resolve=>setTimeout(resolve,millis));

/**
 * @typedef {Object<string,*>} Response
 * @property {number} status
 * @property {Map<String,String>} headers
 * @property {Buffer} body
 */

/**
 * Performs an http request to the local server.
 * @param {string} path
 * @param {Object<string,string>?} extraHeaders
 * @param {Object<string,string>?} form
 * @returns {Promise<Response>}
 */
const request=(path,extraHeaders,form)=>new Promise((resolve,reject)=>{
  const options = {
    host: 'localhost',
    port: port,
    path: path,
    method: form ? 'POST' : 'GET'
  };
  if(extraHeaders) options.headers = extraHeaders;
  if(form){
    options.headers = Object.assign({}, options.headers||{});
    options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
  }
  const request = http.request(options);
  const data = [];
  let status = 0;
  let headers = new Map();
  let error = undefined;
  request.on('error', e=>error=e);
  request.on('response', it=>{
    status = it.statusCode;
    Object.keys(it.headers).forEach(h=>{
      headers.set(h,it.headers[h]);
    });
    it.on('data', it=>data.push(it));
  });
  request.on('close', ()=>{
    if (error) reject(error);
    else resolve(
      {
        status: status,
        headers: headers,
        body: Buffer.concat(data)
      }
    );
  });
  request.setTimeout(3000);
  if(form) request.write(querystring.stringify(form));
  request.end();
});

let server;

const credentials = {
  tester1: {
    hash: sha256b64('password1'),
    data: {
      name: 'Tester 1',
      id: 1
    },
    token: 'a'
  },
  tester2: {
    hash: sha256b64('Pa$$w0rD:(2)'),
    data: {
      name: 'Tester 2',
      id: 2
    },
    token: 'b'
  }
};

before(async()=>{
  const handler = await authHandler(
    {
      realm: 'test',
      privateKey: {
        path: 'test/key.pem'
      },
      authenticate: async(username,passwordSha256b64)=>{
        const user=credentials[username];
        if(!user||passwordSha256b64!==user.hash) return null;
        return {
          data: user.data,
          token: user.token
        };
      },
      getUserData: async(username)=>{
        const user=credentials[username];
        if(!user) return null;
        return {
          data: user.data,
          token: user.token
        };
      },
      revalidate: async(username,data)=>{
        const user=credentials[username];
        return user&&user.token===data.token;
      },
      revalidateAfter: 350,
      updateUserDataAfter: 500
    },
    {
      accept: (request,response)=>{
        return request.url==='/test'?{request,response}:null;
      },
      handle: (acceptor)=>{
        const { request, response } = acceptor;
        const cookie=request.headers['Cookie']||'null';
        response.writeHead(200,{'Content-Type':'text/plain'});
        response.write(cookie);
        response.end();
      }
    }
  );
  server = http.createServer((request,response)=>{
    const accepted=handler.accept(request,response,'localhost','127.0.0.1');
    if(accepted) handler.handle(accepted);
    else{
      response.writeHead(404);
      response.end();
    }
  });
  server.listen(port);
});

after(()=>{
  server.close();
});


const getNonce=async()=>{
  const response = await request('/.auth/test/nonce');
  const body = response.body.toString();
  const prefix = 'const nonce=\'';
  const suffix = '\';';
  return body.substring(prefix.length,body.length-suffix.length);
};
describe('Unhandled request', ()=>{
  it('Request to /not_handlers', async()=>{
    const response = await request('/not_handled');
    assert.strictEqual(response.status, 404);
  });
});
describe('Unauthorized requests', ()=>{
  it('Request to /test should redirect to the login page', async()=>{
    const response = await request('/test');
    assert.strictEqual(response.status, 401);
    assert.strictEqual(response.headers.get('content-type'), 'text/html');
  });
});
describe('Nonce', ()=>{
  it('Nonce endpoint',async()=>{
    const response = await request('/.auth/test/nonce');
    assert.strictEqual(response.status, 200);
    assert.strictEqual(response.headers.get('content-type'), 'application/javascript');
    const body = response.body.toString();
    const prefix = 'const nonce=\'';
    const suffix = '\';';
    const start = body.indexOf(prefix);
    assert.strictEqual(start, 0);
    const end = body.indexOf(suffix,prefix.length);
    assert.strictEqual(end,body.length-suffix.length);
  });
  it('Nonce changes every time', async()=>{
    const nonces = [ await getNonce(), await getNonce(), await getNonce(), await getNonce() ];
    const grouped = nonces.reduce((prev,cur)=>{prev[cur]=(prev[cur]||0)+1;return prev;},{});
    const entries = Object.entries(grouped);
    assert.strictEqual(entries.length, nonces.length);
    entries.forEach(it=>assert.strictEqual(it[1],1));
  });
  it('Nonce with incorrect realm', async()=>{
    const text1 = `realm|${new Date().getTime()}|${crypto.randomBytes(8).toString('base64')}`;
    const nonce1 = encrypt(text1);
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const response1 = await request('/.auth/test/login', null,{ username, hash, nonce: nonce1 });
    assert.strictEqual(response1.status, 400);
    const text2 = `testing|${new Date().getTime()}|${crypto.randomBytes(8).toString('base64')}`;
    const nonce2 = encrypt(text2);
    const response2 = await request('/.auth/test/login', null,{ username, hash, nonce: nonce2 });
    assert.strictEqual(response2.status, 400);
  });
  it('Nonce with no random bytes', async()=>{
    const text = `test|${new Date().getTime()}`;
    const nonce = encrypt(text);
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 400);
  });
  it('Expired nonce', async()=>{
    const nonce = 'JE8zbRSy1XSvMG1EE0L6J0RLkkvj_1j8NkURXf1EnEA6cBHxtmMm1NEQecS6LMmR0MTY3vsiV-pDCplsJwv7xw';
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 400);
  });
  it('Dummy nonce', async()=>{
    const nonce='nonce';
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 400);
  });
});
describe('Login', ()=>{
  it('direct get request to login endpoint', async()=>{
    const response = await request('/.auth/test/login');
    assert.strictEqual(response.status, 405);
  });
  it('Login page', async()=>{
    const response1 = await request('/test');
    assert.strictEqual(response1.status, 401);
    assert.strictEqual(response1.headers.get('content-type'), 'text/html');
    assert.strictEqual(response1.headers.get('content-encoding'), 'identity');
    const response2 = await request('/test', { 'Accept-Encoding': 'gzip' });
    assert.strictEqual(response2.status, 401);
    assert.strictEqual(response2.headers.get('content-type'), 'text/html');
    assert.strictEqual(response2.headers.get('content-encoding'), 'gzip');
    const response3 = await request('/test', { 'Accept-Encoding': 'gzip, br' });
    assert.strictEqual(response3.status, 401);
    assert.strictEqual(response3.headers.get('content-type'), 'text/html');
    assert.strictEqual(response3.headers.get('content-encoding'), 'br');
    const response4 = await request('/test', { 'Accept-Encoding': '*' });
    assert.strictEqual(response4.status, 401);
    assert.strictEqual(response4.headers.get('content-type'), 'text/html');
    assert.strictEqual(response4.headers.get('content-encoding'), 'br');
    const response5 = await request('/test', { 'Accept-Encoding': 'identity' });
    assert.strictEqual(response5.status, 401);
    assert.strictEqual(response5.headers.get('content-type'), 'text/html');
    assert.strictEqual(response5.headers.get('content-encoding'), 'identity');
  });
  it('Unknown user', async()=>{
    const username = 'unknown';
    const hash = credentials.tester1.hash;
    const nonce = await getNonce();
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 401);
  });
  it('Wrong password', async()=>{
    const username = 'tester1';
    const hash = sha256b64('password');
    const nonce = await getNonce();
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 401);
  });
  it('Missing username', async()=>{
    const hash = credentials.tester2.hash;
    const nonce = await getNonce();
    const response = await request('/.auth/test/login', null,{ hash, nonce });
    assert.strictEqual(response.status, 400);
  });
  it('Missing password hash', async()=>{
    const username = 'tester1';
    const nonce = await getNonce();
    const response = await request('/.auth/test/login', null,{ username, nonce });
    assert.strictEqual(response.status, 400);
  });
  it('Missing nonce', async()=>{
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const response = await request('/.auth/test/login', null,{ username, hash });
    assert.strictEqual(response.status, 400);
  });
  it('Correct password', async()=>{
    const username = 'tester1';
    const hash = credentials.tester1.hash;
    const nonce = await getNonce();
    const response = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response.status, 303);
    const cookie = response.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    const i = cookie.indexOf('=');
    assert.notStrictEqual(i, -1);
    assert.strictEqual(cookie.substring(0,i), 'auth_token_dGVzdA');
    const j = cookie.indexOf(';');
    assert.strictEqual(j>i, true);
    assert.strictEqual(cookie.indexOf('SameSite',j)>j, true);
    assert.strictEqual(cookie.indexOf('HttpOnly',j)>j, true);
    const jwt = cookie.substring(i+1,j);
    const payload = jwtDecode(jwt);
    assert.strictEqual(payload.sub, username);
    assert.strictEqual((new Date().getTime()-payload.iat)<250, true);
    assert.deepStrictEqual(payload.data.token,credentials.tester1.token);
    assert.deepStrictEqual(payload.data.data,credentials.tester1.data);
  });
  it('Invalid jwt value', async()=>{
    const cookie1 = 'auth_token_dGVzdA=test';
    const response1 = await request('/test', { cookie: cookie1 });
    assert.strictEqual(response1.status, 401);
    const cookie2 = 'auth_token_dGVzdA=test; SameSite; HttpOnly;';
    const response2 = await request('/test', { cookie: cookie2 });
    assert.strictEqual(response2.status, 401);
    const cookie3 = 'auth_token_dGVzdA=eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9; SameSite; HttpOnly;';
    const response3 = await request('/test', { cookie: cookie3 });
    assert.strictEqual(response3.status, 401);
    const cookie4 = 'auth_token_dGVzdA=eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.dummy; SameSite; HttpOnly;';
    const response4 = await request('/test', { cookie: cookie4 });
    assert.strictEqual(response4.status, 401);
    const cookie5 = 'auth_token_dGVzdA=eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.dummy.signature; SameSite; HttpOnly;';
    const response5 = await request('/test', { cookie: cookie5 });
    assert.strictEqual(response5.status, 401);
    const cookie6 = 'auth_token_dGVzdA=eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.test.LpPTzNr7-lVjG61BA9_3W8FbhLbvqMuBnfQxvmldWFA; SameSite; HttpOnly;';
    const response6 = await request('/test', { cookie: cookie6 });
    assert.strictEqual(response6.status, 401);
  });
  it('Invalid jwt signature', async()=>{
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJzdWIiOiJ0ZXN0ZXIxIiwiaWF0IjoxNTcyMjEzMTY3NDM0LCJkYXRhIjp7ImRhdGEiOnsibmFtZSI6IlRlc3RlciAxIiwiaWQiOjF9LCJ0b2tlbiI6ImEifX0.WDfx1h8QzB58nf7Obiij2txw0ro2mkCuqV8wf4fdAv4';
    const cookie = `auth_token_dGVzdA=${jwt}; SameSite; HttpOnly`;
    const response = await request('/test', { cookie: cookie });
    assert.strictEqual(response.status, 401);
  });
  it('Validation', async()=>{
    const username = 'tester1';
    const hash=credentials.tester1.hash;
    const nonce=await getNonce();
    const response1 = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response1.status, 303);
    const cookie = response1.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    credentials.tester1.token='c';
    const response2 = await request('/test', { cookie });
    assert.strictEqual(response2.status, 200);
    await delay(350);
    const response3 = await request('/test', { cookie });
    assert.strictEqual(response3.status, 401);
  });
  it('User data', async()=>{
    const username='tester2';
    const hash=credentials.tester2.hash;
    const nonce=await getNonce();
    const response1 = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response1.status, 303);
    const cookie1 = response1.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    credentials.tester2.data.id=4;
    const response2 = await request('/test', { cookie:cookie1 });
    assert.strictEqual(response2.status, 200);
    await delay(500);
    const response3 = await request('/test', { cookie:cookie1 });
    assert.strictEqual(response3.status, 303);
    const cookie3 = response3.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    const i = cookie3.indexOf('=');
    assert.notStrictEqual(i, -1);
    assert.strictEqual(cookie3.substring(0,i), 'auth_token_dGVzdA');
    const j = cookie3.indexOf(';');
    assert.strictEqual(j>i, true);
    assert.strictEqual(cookie3.indexOf('SameSite',j)>j, true);
    assert.strictEqual(cookie3.indexOf('HttpOnly',j)>j, true);
    const jwt = cookie3.substring(i+1,j);
    const payload = jwtDecode(jwt);
    assert.strictEqual(payload.sub, username);
    assert.strictEqual((new Date().getTime()-payload.iat)<250, true);
    assert.deepStrictEqual(payload.data.token,credentials.tester2.token);
    assert.strictEqual(payload.data.data.id,4);
    delete(credentials.tester2);
    const response4 = await request('/test', { cookie: cookie1 });
    assert.strictEqual(response4.status, 401);
  });
});
describe('Logout', ()=>{
  it('Clear cookie', async()=>{
    const username='tester1';
    const hash=credentials.tester1.hash;
    const nonce=await getNonce();
    const response1 = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response1.status, 303);
    const cookie = response1.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    const response2 = await request('/test', { cookie },{ username, hash, nonce });
    assert.strictEqual(response2.status, 200);
    const response3 = await request('/.auth/test/logout');
    assert.strictEqual(response3.status, 302);
    const cookie2 = response3.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    const i = cookie2.indexOf('=');
    assert.notStrictEqual(i, -1);
    assert.strictEqual(cookie2.substring(0,i), 'auth_token_dGVzdA');
    const j = cookie2.indexOf(';');
    assert.strictEqual(j>i, true);
    assert.strictEqual(cookie.indexOf('SameSite',j)>j, true);
    assert.strictEqual(cookie.indexOf('HttpOnly',j)>j, true);
    const jwt = cookie.substring(i+1,j);
    assert.strictEqual(jwt, '');
  });
});
