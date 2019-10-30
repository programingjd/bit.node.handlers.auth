[![Node.js version](https://img.shields.io/badge/node-%3E%3D11.7.0-blue)](https://nodejs.org)
[![Bit.dev package](https://img.shields.io/badge/%20bit%20-programingjd.node%2Fhandlers%2Fauth-blueviolet)](https://bit.dev/programingjd/node/handlers/auth)
[![GitHub package.json version](https://img.shields.io/github/package-json/v/programingjd/bit.node.handlers.auth)](https://bit.dev/programingjd/node/handlers/auth)
[![GitHub](https://img.shields.io/github/license/programingjd/bit.node.handlers.auth)](LICENSE)
![Travis (.org)](https://img.shields.io/travis/programingjd/bit.node.handlers.auth)
![Coveralls github](https://img.shields.io/coveralls/github/programingjd/bit.node.handlers.auth)

Node.js module.

HTTP handler for adding authentication to a list of handlers.

Authorization is stored in a cookie as an unencrypted JSON Web Token ([JWT](https://jwt.io/)).


## Usage

```javascript
const http = require('http');
const auth = require('@bit/programingjd.node.handlers.auth');

(async()=>{
  // hashing function for passwords: base64 (url safe) of sha256 hash
  const hash = text=>require('crypto').createHash('sha256').update(text).digest('base64').
    replace('+','-').replace('/','-').replace('=','');
  // allowed users and their data
  const credentials = {
    user1: {
      hash: hash('passwordForUser1'),
      data: {
        id: 1,
        name: 'User 1',
        admin: true
      }
    },
    user2: {
      hash: hash('passwordForUser2'),
      data: {
        id: 2,
        name: 'User 2',
        admin: false
      }
    }
  };
  // handlers that require authentication
  const handlers = [

  ];
  // authentication handler
  const handler = await auth(
    {
      primaryKey: {
        path: 'private.key'
      },
      cookie: {
        secure: false,
        httpOnly: false
      },
      authenticate: async(username,passwordHash)=>{
        const user = credentials[username];
        return user && passwordHash === user.passwordHash ? user.data : null;
      },
      getUserData: async(username)=>{
        const user = credentials[username];
        return user ? user.data : null;
      },
      revalidate: async()=>true,
      revalidateAfter: 3600000, // 1 hour
      updateUserDataAfter: 86400000 // 1 day
    },
    ...handlers
  );

  http.createServer((request, response)=>{
    const accepted = handler.accept(request, response, 'not_used', request.connection.remoteAddress);
    if (accepted) {
      handler.handle(accepted);
    } else {
      response.writeHead(404);
      response.end();
    }
  }).listen(80); 
})();
```

## Options

- `realm`  (string)

  The name of the protected realm.
  
  It defaults to `'default'`. If your server has multiple authentication handlers for
  different sets of handlers, then you should specify a different realm name for each
  authentication handler, because that name is used as the basis for the name of
  the cookie.
  
- `privateKey.path`  (string)

  The path of the private key used for the JWT secret and the generation of the nonce.
  
  Sample code to create a valid key (note that you can increase the modulusLength but this will have the
  side effect of having longer nonce as well).
  
  ``` javascript
  const { privateKey } = require('crypto').generateKeyPairSync('rsa',{
    modulusLength: 512,
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem',
    }
  });
  require('fs').writeFileSync('private.key',privateKey);
  ```
  
- `cookie.secure`  (boolean)

  If the server is using the handlers with http and not https, then you need to set
  to disable the secure cookie option.
  
  It defaults to `true` (the cookie is sent with the Secure attribute).
  
- `cookie.httpOnly`  (boolean)

  If you need the user data to be accessible from javascript on the page, then you
  need to set httpOnly to `false`. You can then get the cookie from javascript
  (the cookie name is 'auth_' followed by the base64 (url safe) of the realm name)
  and then extract the user data from the JWT value (base64 url safe decode the part
  between the two dots).
  
  It defaults to `true` (the cookie is not accessible from the page).

