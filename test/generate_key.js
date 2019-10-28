const { privateKey } = require('crypto').generateKeyPairSync('rsa',{
  modulusLength: 2048,
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  }
});
require('fs').writeFileSync('key.pem',privateKey);
