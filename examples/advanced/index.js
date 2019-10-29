const auth = require('../../auth');
const http = require('http');
const fs = require('fs').promises;

(async()=>{
  const sha1=(text)=>{
    return require('crypto').createHash('sha1').update(text).digest('hex');
  };
  const users={
    'user1': {
      passwordHash: sha1('password1'),
      data: {
        name: 'User 1',
        id: 1
      }
    },
    'user2': {
      passwordHash: sha1('password2'),
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
        secure: false,
        httpOnly: false
      },
      authenticate: async(username,passwordHash)=>{
        const user = users[username];
        return user && passwordHash === user.passwordHash ? user.data : null;
      },
      getUserData: async(username)=>{
        const user = users[username];
        return user ? user.data: null;
      },
      revalidate: async()=>true,
      loginPage: {
        content: async()=>fs.readFile('login.html')
      }
    },
    {
      accept(request, response){
        if(request.url === '/') return { response, file: 'index.html' };
        return null;
      },
      handle(acceptor){
        const { response, file } = acceptor;
        response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache' });
        (async()=>{
          const content = await fs.readFile(file);
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
