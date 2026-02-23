const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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
let users = {}; // { username: { passwordHash: '...' } }

// Загружаем пользователей из файла, если есть
const usersFile = path.join(__dirname, 'users.json');
try {
    users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
} catch (e) {
    users = {};
}

function saveUsers() {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function broadcastOnline() {
    let onlineUsers = {};
    for (let name in clients) onlineUsers[name] = true;

    for (let name in clients) {
        clients[name].send(JSON.stringify({
            type: "onlineList",
            users: onlineUsers
        }));
    }
}

wss.on('connection', ws => {
    ws.on('message', message => {
        let data = JSON.parse(message);

        if (data.type === "auth") {
            const name = data.name;
            const password = data.password;

            // Проверяем, существует ли пользователь
            if (users[name]) {
                // Проверяем пароль
                if (users[name].passwordHash !== hashPassword(password)) {
                    ws.send(JSON.stringify({ type: "error", message: "Неверный пароль" }));
                    ws.close();
                    return;
                }
            } else {
                // Новый пользователь – регистрируем
                users[name] = { passwordHash: hashPassword(password) };
                saveUsers();
            }

            // Успешная аутентификация
            ws.name = name;
            clients[name] = ws;
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
