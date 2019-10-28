const { privateKey } = require('crypto').generateKeyPairSync('rsa',{
  modulusLength: 512,
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  }
});
require('fs').writeFileSync('key.pem',privateKey);
