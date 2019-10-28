[![Node.js version](https://img.shields.io/badge/node-%3E%3D11.7.0-blue)](https://nodejs.org)
[![Bit.dev package](https://img.shields.io/badge/%20bit%20-programingjd.node%2Fhandlers%2Fauth-blueviolet)](https://bit.dev/programingjd/node/handlers/auth)
[![GitHub package.json version](https://img.shields.io/github/package-json/v/programingjd/bit.node.handlers.auth)](https://bit.dev/programingjd/node/handlers/auth)
[![GitHub](https://img.shields.io/github/license/programingjd/bit.node.handlers.auth)](LICENSE)
![Travis (.org)](https://img.shields.io/travis/programingjd/bit.node.handlers.auth)
![Coveralls github](https://img.shields.io/coveralls/github/programingjd/bit.node.handlers.auth)

Node.js module.



## Usage

```javascript
const http = require('http');
const auth = require('@bit/programingjd.node.handlers.auth');

(async()=>{
  const handler = await auth({});
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

- `root`  (string)

  The path of the directory to serve.
  
  It defaults to `'www'`.
  
- `prefix`  (string)

  The path prefix to use for serving the files.
  
  It defaults to `''` (no prefix).
  
  Example:
  
  `root = 'www'` and `prefix = 'files'`
  
  `/files/doc.html` on the server points to `./www/doc.html` on disk.
  
- `disallowSharedCache`  (boolean)

  If you require authorization to access these static files, you can prevent browsers
  from storing the cached data in a shared cache  by setting this option to `true`.
  
  It defaults to `false` (caching in a shared cache is allowed).

