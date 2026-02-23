const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USERS_FILE = path.join(__dirname, 'users.json');

function loadUsers() {
    try {
        return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch {
        return {};
    }
}

function saveUsers(users) {
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
    fs.renameSync(tmp, USERS_FILE);
}

function hashPassword(password, saltHex) {
    return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100000, 64, 'sha512').toString('hex');
}

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

const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 }); // 20 MB

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
    ws.authenticated = false;

    ws.on('message', message => {
        let data;
        try {
            data = JSON.parse(message);
        } catch {
            return;
        }

        if (data.type === "register") {
            const nick = (data.nick || '').trim();
            const password = data.password || '';

            if (!/^[a-zA-Z0-9_]{1,32}$/.test(nick)) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Invalid nick (1–32 chars, a-z A-Z 0-9 _)" }));
                return;
            }
            if (password.length < 6 || password.length > 128) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Password must be 6–128 characters" }));
                return;
            }

            const users = loadUsers();
            if (users[nick]) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Nick already taken" }));
                return;
            }

            const saltHex = crypto.randomBytes(32).toString('hex');
            const hash = hashPassword(password, saltHex);
            users[nick] = { hash, salt: saltHex };
            saveUsers(users);

            ws.authenticated = true;
            ws.name = nick;
            clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: "authResult", success: true, nick }));
            return;
        }

        if (data.type === "login") {
            const nick = (data.nick || '').trim();
            const password = data.password || '';

            const users = loadUsers();
            if (!users[nick]) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Unknown nick" }));
                return;
            }

            const expected = hashPassword(password, users[nick].salt);
            if (expected !== users[nick].hash) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Wrong password" }));
                return;
            }

            // Kick existing session with the same nick
            if (clients[nick] && clients[nick] !== ws) {
                try {
                    clients[nick].send(JSON.stringify({ type: "kicked" }));
                    clients[nick].close();
                } catch {}
            }

            ws.authenticated = true;
            ws.name = nick;
            clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: "authResult", success: true, nick }));
            return;
        }

        if (!ws.authenticated) return;

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

        if (data.type === "typing") {
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            }
        }
    });

    ws.on('close', () => {
        if (ws.name && clients[ws.name] === ws) {
            delete clients[ws.name];
            broadcastOnline();
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log("Server started on port " + PORT);
});
