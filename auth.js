const http2=require('http');
const fs=require('fs').promises;
const zlib=require('zlib');
const crypto=require('crypto');
const query=require('querystring');

/**
 * Performs a gzip compression with the max compression level.
 * @private
 * @param {Buffer} uncompressed
 * @returns {Promise<Buffer>}
 */
const gz=async uncompressed=>{
  return new Promise((resolve)=>{
    const options = { level: 9 };
    zlib.gzip(uncompressed, options,(err,compressed)=>resolve(compressed))
  });
};

/**
 * Performs a brotli compression with the max compression level.
 * @private
 * @param {Buffer} uncompressed
 * @returns {Promise<Buffer>}
 */
const br=async (uncompressed)=>{
  return new Promise((resolve)=>{
    const options = {
      params: {
        [ zlib.constants.BROTLI_PARAM_MODE ]: zlib.constants.BROTLI_MODE_TEXT,
        [ zlib.constants.BROTLI_PARAM_QUALITY ]: zlib.constants.BROTLI_MAX_QUALITY,
        [ zlib.constants.BROTLI_PARAM_SIZE_HINT ]: uncompressed.length
      }
    };
    zlib.brotliCompress(uncompressed, options, (err,compressed)=>resolve(compressed))
  });
};

/**
 * Supported encodings.
 * @private
 * @readonly
 * @enum {string}
 */
const Encodings={
  identity: 'identity',
  gzip: 'gzip',
  brotli: 'br'
};

/**
 * Returns the best supported encoding.
 * @private
 * @param {http2.IncomingHttpHeaders} headers
 * @returns {Encodings}
 */
const bestSupportedEncoding=headers=>{
  const acceptEncodingHeader=(headers['accept-encoding']||'').trim();
  if(!acceptEncodingHeader) return Encodings.identity;
  if(acceptEncodingHeader==='*') return Encodings.brotli;
  const list=acceptEncodingHeader.split(',').map(it=>it.replace(/;.*$/g,'').trim());
  if(list.indexOf('br')!==-1) return Encodings.brotli;
  if(list.indexOf('gzip')!==-1) return Encodings.gzip;
  return Encodings.identity;
};

/**
 * @param {http2.IncomingMessage} request
 * @returns {Promise<string>}
 */
const body=async request=>new Promise(resolve=>{
  let data='';
  request.on('data',chunk=>data+=chunk);
  request.on('end',()=>resolve(data));
});

/**
 * @param {string|Buffer} data
 */
const b64urlEncode=(data)=>{
  /** @type {Buffer} */
  const buffer=typeof data==='string'?Buffer.from(data):data;
  return buffer.toString('base64').
    replace(/[+]/g,'-').
    replace(/[/]/g,'_').
    replace(/[=]+$/,'');
};

/**
 * @param {string} data
 * @returns {Buffer}
 */
const b64urlDecode=(data)=>{
  return Buffer.from(data.
    replace(/[-]/g,'+').
    replace(/[_]/g,'/'),
    'base64');
};

const jwtHeader=JSON.stringify({alg:'HS256',typ:'jwt'});
const jwtHeaderBase64=b64urlEncode(jwtHeader);

/**
 * @param {string} privateKeySha256
 * @param {string} username
 * @param {Object<string,*>} data
 * @returns {string}
 */
const jwtEncode=(privateKeySha256,username,data)=>{
  const payload={
    sub: username,
    iat: new Date().getTime(),
    data: data
  };
  const b64=b64urlEncode(JSON.stringify(payload));
  const hmac=crypto.createHmac('SHA256',privateKeySha256);
  const signature=b64urlEncode(hmac.update(jwtHeaderBase64).update('.').update(b64).digest());
  return `${jwtHeaderBase64}.${b64}.${signature}`;
};

/**
 * @param {string} privateKeySha256
 * @param {string} jwt
 * @returns {{username:string,timestamps:number,data:Object<string,*>}|null}
 */
const jwtDecode=(privateKeySha256,jwt)=>{
  if(jwt.indexOf(jwtHeaderBase64)===-1||jwt.indexOf('.')!==jwtHeaderBase64.length) return null;
  const index=jwt.indexOf('.',jwtHeaderBase64.length+1);
  if(index===-1) return null;
  try{
    const signature=jwt.substring(index+1);
    const hmac=crypto.createHmac('SHA256',privateKeySha256);
    if(signature!==b64urlEncode(hmac.update(jwt.substring(0,index)).digest())) return null;
    const payload=JSON.parse(b64urlDecode(jwt.substring(jwtHeaderBase64.length+1,index)).toString());
    return {
      username:payload.sub,
      timestamp:payload.iat,
      data:payload.data
    };
  }catch{
    return null;
  }
};

/**
 * @param {KeyObject} privateKey
 * @param {string} realm
 * @returns {string}
 */
const createNonce=(privateKey,realm)=>{
  const text=`${realm}|${new Date().getTime()}|${crypto.randomBytes(8).toString('base64')}`;
  return b64urlEncode(crypto.privateEncrypt(privateKey,Buffer.from(text)));
};

/**
 * @param {KeyObject} privateKey
 * @param {string} realm
 * @param {string} nonce
 * @returns {boolean}
 */
const validateNonce=(privateKey,realm,nonce)=>{
  try{
    const text=crypto.publicDecrypt(privateKey,b64urlDecode(nonce)).toString();
    if(text.indexOf(realm)!==0) return false;
    if(text.charAt(realm.length)!=='|') return false;
    const i=text.indexOf('|',realm.length+1);
    if(i=== -1) return false;
    const dt=new Date().getTime()-parseInt(text.substring(realm.length+1,i));
    return dt<60000;
  }catch(ignore){
    return false;
  }
};

/**
 * @name UserInfo
 * @typedef {Object<string,*>} UserInfo
 * @property {string} password
 * @property {Object<string,*>} [data]
 */

/**
 * @name RealmOptions
 * @template T
 * @typedef {Object<string,*>} RealmOptions
 * @property {string} [realm]
 * @property {{path:string}} privateKey
 * @property {function(username:string,passwordSha256b64:string):Promise<T|null>} authenticate
 * @property {function(username:string):Promise<T|null} getUserData
 * @property {function(username:string,userData:T):Promise<boolean>} revalidate
 * @property {number} [revalidateAfter]
 * @property {number} [updateUserDataAfter]
 * @property {{page:{styles:string}}} login
 */

/**
 * @name AuthAcceptor
 * @template T
 * @typedef {Object<string,*>} AuthAcceptor
 * @property {http2.IncomingMessage} request
 * @property {http2.ServerResponse} response
 * @property {string} hostname
 * @property {
 *   {
 *     accept: function(
 *       request:http2.IncomingMessage,
 *       response:http2.ServerResponse,
 *       hostname:string,
 *       remoteAddress:string
 *     ):T,
 *     handle:function(T)
 *   }
 * } handler
 * @property {T} acceptor
 */

/**
 * @template T
 * @template A
 * @param {RealmOptions} options
 * @param {
 *   ...{
 *     accept:function(
 *       request:http2.IncomingMessage,
 *       response:http2.ServerResponse,
 *       hostname:string,
 *       remoteAddress:string
 *     ):A?,
 *     handle:function(A)
 *   }
 * } handlers
 * @returns {
 *   Promise<{
 *     accept: function(
 *       request:http2.IncomingMessage,
 *       response:http2.ServerResponse,
 *       hostname:string,
 *       remoteAddress:string
 *     ):T?,
 *     handle:function(T)
 *   }>
 * }
 */
module.exports=async (options,...handlers)=>{
  const { realm='default' }=options;
  const revalidateAfter=
    typeof options.revalidateAfter==='number'?options.revalidateAfter:Number.MAX_SAFE_INTEGER;
  const updateUserDataAfter=
    typeof options.updateUserDataAfter==='number'?options.updateUserDataAfter:Number.MAX_SAFE_INTEGER;
  const privateKeyContent=await fs.readFile(options.privateKey.path);
  const privateKey=crypto.createPrivateKey(privateKeyContent);
  const privateKeySha256=crypto.createHash("SHA256").update(privateKeyContent.toString()).digest().toString();
  const loginData=Buffer.from(
    `<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<title>${options.realm||'Login'}</title>
<script src="./nonce"></script>
<style>
html{font:calc(1vmin + 1vmax) sans-serif;width:100%;height:100%;margin:0;padding:0;background:#eee}
body{
  min-width:100%;min-height:100%;margin:0;padding:1em;box-sizing:border-box;
  display:grid;grid-template-columns:auto;grid-template-rows:auto;justify-content:center;align-items:center;
}
form{
  font-size:1.5em;
  display:grid;grid-template-columns:auto;grid-template-rows:repeat(3,auto);grid-gap:1em;
  justify-content:center;justify-items:center;align-items:center;align-content:center;
}
input{font-size:inherit;padding:.25em .5em}
button{font-size:inherit;padding:.5em 1em;margin-top:1em}
${((options.login||{}).page||{}).styles||''}
</style>
</head>
<body>
<form name="login" method="post">
<input required name="username" type="text" autocomplete="username" placeholder="username">
<input required type="password" autocomplete="current-password" placeholder="password">
<input type="hidden" name="hash">
<input type="hidden" name="nonce">
<button type="submit">Login</button>
</form>
<script>
const sha256b64=async data=>{
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(data));
  const hex=Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  return btoa(hex).replace(/[+]/g,'-').replace(/[/]/g,'_').replace(/[=]+$/,'');
};
const f=document.forms.namedItem('login');
const p=f.querySelector('input[type=password]');
const u=async _=>{
  console.log('submit');
  f.nonce.value=nonce;
  f.hash.value=await sha256b64(p.value);
};
p.addEventListener('change',u,false);
p.addEventListener('keydown',e=>{
  if(e.key==='Enter'&&f.username.value){
    e.preventDefault();
    u().then(_=>f.submit());
  }
});
</script>
</body>
</html>`
  );
  const login={
    identity: loginData,
    gz: await gz(loginData),
    br: await br(loginData)
  };
  const loginPath=`/.auth/${encodeURIComponent(realm)}/login`;
  const logoutPath=`/.auth/${encodeURIComponent(realm)}/logout`;
  const noncePath=`/.auth/${encodeURIComponent(realm)}/nonce`;
  const cookieStart=`auth_token_${b64urlEncode(realm)}=`;
  const clearCookie=`${cookieStart}; Secure; HttpOnly; SameSite=Strict;`;
  /**
   * @param {http2.IncomingMessage} request
   * @param {http2.ServerResponse} response
   */
  const loginPage=(request,response)=>{
    const encoding=bestSupportedEncoding(request.headers);
    response.writeHead(401, {
      'Content-Type': 'text/html',
      'Content-Encoding': encoding
    });
    response.end(login[encoding]);
  };
  return {
    /**
     * @param {http2.IncomingMessage} request
     * @param {http2.ServerResponse} response
     * @param {string} hostname
     * @param {string} remoteAddress
     * @returns {AuthAcceptor|null}
     */
    accept: (request,response,hostname,remoteAddress)=>{
      if(request.url===logoutPath||request.url===noncePath||request.url===loginPath){
        return { request, response, hostname, handler: undefined, accepted: undefined };
      }
      for(const handler of handlers){
        const accepted=handler.accept(request,response,hostname,remoteAddress);
        if(accepted) return { request, response, hostname, handler, accepted };
      }
      return null;
    },
    /**
     * @param {AuthAcceptor} acceptor
     */
    handle: (acceptor)=>{
      const { request, response, handler, accepted } = acceptor;
      if(request.url===logoutPath){
        response.writeHead(302,{'Set-Cookie':clearCookie});
        response.end();
      }
      else if(request.url===noncePath){
        response.writeHead(200,{'Content-Type':'application/javascript'});
        const nonce=createNonce(privateKey,realm);
        response.end(`const nonce='${nonce}';`);
      }
      else if(request.url===loginPath){
        const method=request.method.toLowerCase();
        if(method==='post'){
          (async()=>{
            const q=await body(request);
            const params=query.parse(q);
            const username=params['username'];
            const hash=params['hash'];
            const nonce=params['nonce'];
            if(username&&hash&&nonce&&validateNonce(privateKey,realm,nonce)){
              const data=await options.authenticate(username,hash);
              if(data===null){
                loginPage(request,response);
              }
              else{
                const jwt=jwtEncode(privateKeySha256,username,data);
                const cookie=`${cookieStart}${jwt}; Secure; HttpOnly; SameSite=strict;`;
                response.writeHead(303,{'Location':request.url,'Set-Cookie':cookie});
                response.end();
              }
            }
            else{
              response.writeHead(400);
              response.end();
            }
          })();
        }
        else{
          response.writeHead(405);
          response.end();
        }
      }
      else{
        const cookies=request.headers['cookie']||'';
        const i=cookies.indexOf(cookieStart);
        if(i===-1) loginPage(request,response);
        else{
          const j=cookies.indexOf(';',i+cookieStart.length);
          const jwt=
            j===-1?cookies.substring(i+cookieStart.length):cookies.substring(i+cookieStart.length,j);
          const decoded = jwtDecode(privateKeySha256,jwt);
          if(!decoded) loginPage(request,response);
          else{
            const { username, timestamp, data } = decoded;
            const dt=new Date().getTime()-timestamp;
            (async()=>{
              if(dt>revalidateAfter){
                if(!(await options.revalidate(username,data))) return loginPage(request,response);
              }
              if(dt>updateUserDataAfter){
                const updated=await options.getUserData(username);
                if(!updated) return loginPage(request,response);
                const jwt=jwtEncode(privateKeySha256,username,updated);
                const cookie=`${cookieStart}${jwt}; Secure; HttpOnly; SameSite=strict;`;
                response.writeHead(303,{'Location':request.url,'Set-Cookie':cookie});
                response.end();
              }
              else handler.handle(accepted);
            })();
          }
        }
      }
    }
  };

};
