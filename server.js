const http = require('http');

const server = http.createServer((red,res) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Hello, World\n')
});

const port = 3000;
server.listen(port, () => {
    console.log('server running at http://localhost:${port}/');
});