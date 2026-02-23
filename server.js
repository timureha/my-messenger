const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');

const server = http.createServer((req, res) => {
    let filePath = path.join(__dirname, req.url === "/" ? "index.html" : req.url);

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404);
            res.end("Not found");
        } else {
            res.writeHead(200);
            res.end(content);
        }
    });
});

const wss = new WebSocket.Server({ server });

let clients = {};

function broadcastOnline() {
    let users = {};
    for (let name in clients) users[name] = true;

    for (let name in clients) {
        clients[name].send(JSON.stringify({
            type: "onlineList",
            users
        }));
    }
}

wss.on('connection', ws => {

    ws.on('message', message => {
        let data = JSON.parse(message);

        if (data.type === "auth") {
            ws.name = data.name;
            clients[data.name] = ws;
            broadcastOnline();
        }

        if (data.type === "message") {
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            }
        }

        if (data.type === "signal") {
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            }
        }
    });

    ws.on('close', () => {
        if (ws.name) {
            delete clients[ws.name];
            broadcastOnline();
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log("Server started on port " + PORT);
});