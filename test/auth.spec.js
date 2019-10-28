const assert= require('assert');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const querystring = require('querystring');
const authHandler = require('../auth');

const port = 8080;

const privateKeyContent=fs.readFileSync('test/key.pem');
const privateKeySha256=crypto.createHash("SHA256").update(privateKeyContent.toString()).digest().toString();

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
    options.headers = Object.fromEntries(
      [...Object.entries(options.headers||{}),['Content-Type','application/x-www-form-urlencoded']]
    );
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
});
describe('Login', ()=>{
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
  it('Validation', async()=>{
    const username='tester1';
    const hash=credentials.tester1.hash;
    const nonce=await getNonce();
    const response1 = await request('/.auth/test/login', null,{ username, hash, nonce });
    assert.strictEqual(response1.status, 303);
    const cookie = response1.headers.get('set-cookie').find(it=>it.indexOf('auth_token_')===0);
    credentials.tester1.token='c';
    const response2 = await request('/test', { cookie },{ username, hash, nonce });
    assert.strictEqual(response2.status, 200);
    await delay(350);
    const response3 = await request('/test', { cookie },{ username, hash, nonce });
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
    const response2 = await request('/test', { cookie:cookie1 },{ username, hash, nonce });
    assert.strictEqual(response2.status, 200);
    await delay(500);
    const response3 = await request('/test', { cookie:cookie1 },{ username, hash, nonce });
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
  });
});
describe('Logout', ()=>{
  it('Clear cookie', async()=>{
    const username='tester2';
    const hash=credentials.tester2.hash;
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
