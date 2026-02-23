const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USERS_FILE = path.join(__dirname, 'users.json');
const QUEUE_FILE = path.join(__dirname, 'queue.json');

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch { return {}; }
}

function saveUsers(users) {
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
    fs.renameSync(tmp, USERS_FILE);
}

function loadQueue() {
    try { return JSON.parse(fs.readFileSync(QUEUE_FILE, 'utf8')); }
    catch { return {}; }
}

function saveQueue(queue) {
    const tmp = QUEUE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(queue));
    fs.renameSync(tmp, QUEUE_FILE);
}

function enqueue(nick, msg) {
    const queue = loadQueue();
    if (!queue[nick]) queue[nick] = [];
    queue[nick].push(msg);
    saveQueue(queue);
}

function flushQueue(nick) {
    const queue = loadQueue();
    const msgs = queue[nick] || [];
    if (msgs.length) {
        delete queue[nick];
        saveQueue(queue);
    }
    return msgs;
}

function hashPassword(password, saltHex) {
    return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100000, 64, 'sha512').toString('hex');
}

const server = http.createServer((req, res) => {
    let filePath = path.join(__dirname, req.url === "/" ? "index.html" : req.url);
    fs.readFile(filePath, (err, content) => {
        if (err) { res.writeHead(404); res.end("Not found"); }
        else { res.writeHead(200); res.end(content); }
    });
});

const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 });

let clients = {};

function broadcastOnline() {
    const users = {};
    for (const name in clients) users[name] = true;
    for (const name in clients) {
        clients[name].send(JSON.stringify({ type: "onlineList", users }));
    }
}

wss.on('connection', ws => {
    ws.authenticated = false;

    ws.on('message', message => {
        let data;
        try { data = JSON.parse(message); } catch { return; }

        // ── Регистрация ──────────────────────────────────────────────────
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
            users[nick] = { hash: hashPassword(password, saltHex), salt: saltHex };
            saveUsers(users);

            ws.authenticated = true;
            ws.name = nick;
            clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: "authResult", success: true, nick }));
            return;
        }

        // ── Вход ─────────────────────────────────────────────────────────
        if (data.type === "login") {
            const nick = (data.nick || '').trim();
            const password = data.password || '';

            const users = loadUsers();
            if (!users[nick]) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Unknown nick" }));
                return;
            }
            if (hashPassword(password, users[nick].salt) !== users[nick].hash) {
                ws.send(JSON.stringify({ type: "authResult", success: false, error: "Wrong password" }));
                return;
            }

            if (clients[nick] && clients[nick] !== ws) {
                try { clients[nick].send(JSON.stringify({ type: "kicked" })); clients[nick].close(); } catch {}
            }

            ws.authenticated = true;
            ws.name = nick;
            clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: "authResult", success: true, nick }));

            // Отдать накопленную очередь
            const pending = flushQueue(nick);
            for (const msg of pending) {
                ws.send(JSON.stringify(msg));
            }
            return;
        }

        if (!ws.authenticated) return;

        // ── Проверка существования ника ──────────────────────────────────
        if (data.type === "checkNick") {
            const users = loadUsers();
            ws.send(JSON.stringify({
                type: "nickResult",
                nick: data.nick,
                exists: !!(users[(data.nick || '').trim()])
            }));
            return;
        }

        // ── Сообщение ────────────────────────────────────────────────────
        if (data.type === "message") {
            const users = loadUsers();
            if (!users[data.to]) {
                // получатель не существует — сообщаем отправителю
                ws.send(JSON.stringify({ type: "deliveryError", to: data.to, error: "no_user" }));
                return;
            }
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
                // получатель офлайн — ставим в очередь
                enqueue(data.to, data);
            }
        }

        // ── Сигнал (WebRTC) ──────────────────────────────────────────────
        if (data.type === "signal") {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
        }

        // ── Typing ───────────────────────────────────────────────────────
        if (data.type === "typing") {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
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
server.listen(PORT, () => console.log("Server started on port " + PORT));
