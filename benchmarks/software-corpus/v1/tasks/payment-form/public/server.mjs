import {DatabaseSync} from 'node:sqlite';
import {createInterface} from 'node:readline';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {payment} from './api.mjs';
import {submitForm} from './client.mjs';

const db = new DatabaseSync(process.env.PAYMENT_STATE || '/state/state.sqlite');
db.exec('CREATE TABLE payments(id INTEGER PRIMARY KEY,amount_minor INTEGER NOT NULL)');
const send = request => payment(db, request);
if (process.argv.includes('--http')) {
  createServer(async (req,res) => {
    if (req.method === 'POST' && req.url === '/payments') {
      let body = '';for await (const part of req) body += part;
      const result = send(JSON.parse(body));res.writeHead(result.status,{'content-type':'application/json'});res.end(JSON.stringify(result));return;
    }
    const name = req.url === '/' ? 'index.html' : req.url === '/client.mjs' ? 'client.mjs' : null;
    if (!name) {res.writeHead(404);res.end();return;}
    res.writeHead(200,{'content-type':name.endsWith('.html')?'text/html':'text/javascript'});res.end(await readFile(new URL(name,import.meta.url)));
  }).listen(Number(process.env.PORT || 8080),'127.0.0.1');
} else {
  for await (const line of createInterface({input:process.stdin})) {
    const request=JSON.parse(line);
    console.log(JSON.stringify(request.op === 'api' ? send(request) : await submitForm(request.value,send)));
  }
  db.close();
}
