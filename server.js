const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const USERS_FILE  = path.join(__dirname, 'users.json');
const QUEUE_FILE  = path.join(__dirname, 'queue.json');
const GROUPS_FILE = path.join(__dirname, 'groups.json');

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

function loadGroups() {
    try { return JSON.parse(fs.readFileSync(GROUPS_FILE, 'utf8')); }
    catch { return {}; }
}

function saveGroups(groups) {
    const tmp = GROUPS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(groups, null, 2));
    fs.renameSync(tmp, GROUPS_FILE);
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
let lastSeen = {}; // nick -> timestamp

function broadcastOnline() {
    const users = {};
    for (const name in clients) users[name] = true;
    for (const name in clients) {
        clients[name].send(JSON.stringify({ type: "onlineList", users, lastSeen }));
    }
}

// Отправить сообщение всем участникам группы кроме отправителя
function deliverToGroup(groupId, msg, senderNick) {
    const groups = loadGroups();
    const group = groups[groupId];
    if (!group) return;
    for (const member of group.members) {
        if (member === senderNick) continue;
        if (clients[member]) {
            clients[member].send(JSON.stringify(msg));
        } else {
            enqueue(member, msg);
        }
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

            // Отдать список групп, в которых состоит пользователь
            const groups = loadGroups();
            const myGroups = {};
            for (const [id, g] of Object.entries(groups)) {
                if (g.members.includes(nick)) myGroups[id] = g;
            }
            if (Object.keys(myGroups).length > 0) {
                ws.send(JSON.stringify({ type: "groupList", groups: myGroups }));
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
                ws.send(JSON.stringify({ type: "deliveryError", to: data.to, error: "no_user" }));
                return;
            }
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
                enqueue(data.to, data);
            }
        }

        // ── Редактировать сообщение ──────────────────────────────────────
        if (data.type === "edit") {
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
                enqueue(data.to, data);
            }
        }

        // ── Удалить сообщение ────────────────────────────────────────────
        if (data.type === "delete") {
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
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

        // ── Создать группу ───────────────────────────────────────────────
        if (data.type === "createGroup") {
            // data: { type, name, members: [...nicks] }
            const groupName = (data.name || '').trim();
            if (!groupName || groupName.length > 64) return;
            const members = Array.isArray(data.members) ? data.members : [];
            if (!members.includes(ws.name)) members.push(ws.name);
            if (members.length < 2) return;

            const users = loadUsers();
            // проверить что все участники существуют
            for (const m of members) {
                if (!users[m]) return;
            }

            const groups = loadGroups();
            const groupId = 'g_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
            groups[groupId] = { id: groupId, name: groupName, members, creator: ws.name };
            saveGroups(groups);

            const groupInfo = groups[groupId];
            // уведомить всех участников
            for (const member of members) {
                const msg = JSON.stringify({ type: "groupCreated", group: groupInfo });
                if (clients[member]) {
                    clients[member].send(msg);
                } else {
                    enqueue(member, { type: "groupCreated", group: groupInfo });
                }
            }
            return;
        }

        // ── Добавить участника в группу ──────────────────────────────────
        if (data.type === "addGroupMember") {
            // data: { type, groupId, nick }
            const nick = (data.nick || '').trim();
            if (!nick) return;
            const users = loadUsers();
            if (!users[nick]) {
                ws.send(JSON.stringify({ type: "addMemberError", groupId: data.groupId, error: "no_user" }));
                return;
            }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            if (group.members.includes(nick)) {
                ws.send(JSON.stringify({ type: "addMemberError", groupId: data.groupId, error: "already_member" }));
                return;
            }
            group.members.push(nick);
            saveGroups(groups);
            // уведомить всех текущих участников (включая отправителя) об обновлённой группе
            const notif = { type: "groupMemberAdded", groupId: data.groupId, nick, group };
            for (const member of group.members) {
                if (clients[member]) {
                    clients[member].send(JSON.stringify(notif));
                } else {
                    enqueue(member, notif);
                }
            }
            return;
        }

        // ── Групповое сообщение ──────────────────────────────────────────
        if (data.type === "groupMessage") {
            // data: { type, groupId, from, text, mediaType, mediaData, fileName, ts, id }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── Редактировать групповое сообщение ────────────────────────────
        if (data.type === "groupEdit") {
            // data: { type, groupId, from, id, text }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── Удалить групповое сообщение ──────────────────────────────────
        if (data.type === "groupDelete") {
            // data: { type, groupId, from, id }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── Групповой typing ─────────────────────────────────────────────
        if (data.type === "groupTyping") {
            // data: { type, groupId, from }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── Реакция (ЛС) ─────────────────────────────────────────────────
        if (data.type === "reaction") {
            // data: { type, from, to, msgId, emoji }  (emoji=null — снять реакцию)
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }

        // ── Реакция (группа) ─────────────────────────────────────────────
        if (data.type === "groupReaction") {
            // data: { type, from, groupId, msgId, emoji }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }

        // ── Прочитано (ЛС) ───────────────────────────────────────────────
        if (data.type === "read") {
            // data: { type, from, to, lastId }
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            }
            return;
        }

        // ── Прочитано (группа) ───────────────────────────────────────────
        if (data.type === "groupRead") {
            // data: { type, from, groupId, lastId }
            const groups = loadGroups();
            const group = groups[data.groupId];
            if (!group || !group.members.includes(ws.name)) return;
            deliverToGroup(data.groupId, data, ws.name);
            return;
        }
    });

    ws.on('close', () => {
        if (ws.name && clients[ws.name] === ws) {
            lastSeen[ws.name] = Date.now();
            delete clients[ws.name];
            broadcastOnline();
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server started on port " + PORT));
