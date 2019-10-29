const auth = require('../auth');
const http = require('http');
const fs = require('fs').promises;

(async()=>{
  const sha256b64=(text)=>{
    return require('crypto').createHash('sha256').update(text).digest('base64').
      replace('+','-').replace('/','_').replace('=','');
  };
  const users={
    'user1': {
      passwordSha256b64: sha256b64('password1'),
      data: {
        name: 'User 1',
        id: 1
      }
    },
    'user2': {
      passwordSha256b64: sha256b64('password2'),
      data: {
        name: 'User 2',
        id: 2
      }
    }
  };
  const handler = await auth(
    {
      privateKey: {
        path: 'key.pem'
      },
      cookie: {
        secure: false
      },
      authenticate: async(username,passwordSha256b64)=>{
        const user = users[username];
        return user && passwordSha256b64 === user.passwordSha256b64 ? user.data : null;
      },
      getUserData: async(username)=>{
        const user = users[username];
        return user ? user.data: null;
      },
      revalidate: async()=>true
    },
    {
      accept(request, response){
        const page = [ 'page1', 'page2' ].find(it=>request.url===`/${it}`);
        if(page) return { response, page };
        return null;
      },
      handle(acceptor){
        const { response, page } = acceptor;
        response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
        (async()=>{
          const content = await fs.readFile(`${page}.html`);
          response.end(content);
        })();
      }
    }
  );

  http.createServer((request,response)=>{
    const accepted=handler.accept(request,response,'localhost','127.0.0.1');
    if(accepted) handler.handle(accepted);
    else{
      response.writeHead(404);
      response.end();
    }
  }).listen(80);
})();
