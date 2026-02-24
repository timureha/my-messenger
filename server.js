'use strict';
const WebSocket = require('ws');
const http      = require('http');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const { MongoClient } = require('mongodb');
const webpush   = require('web-push');

// ── VAPID (Web Push) ────────────────────────────────────────────────────────
let vapidPublicKey  = process.env.VAPID_PUBLIC_KEY;
let vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;
if (!vapidPublicKey || !vapidPrivateKey) {
    const keys = webpush.generateVAPIDKeys();
    vapidPublicKey  = keys.publicKey;
    vapidPrivateKey = keys.privateKey;
    console.warn('⚠️  VAPID keys not in env — generated for this session only.');
    console.warn('Add to Render environment variables:');
    console.warn('VAPID_PUBLIC_KEY=' + vapidPublicKey);
    console.warn('VAPID_PRIVATE_KEY=' + vapidPrivateKey);
}
webpush.setVapidDetails('mailto:admin@messenger.app', vapidPublicKey, vapidPrivateKey);

// ── MongoDB ─────────────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/messenger';
let db;

async function connectDB() {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db();
    await db.collection('users').createIndex({ nick: 1 }, { unique: true });
    await db.collection('queue').createIndex({ recipient: 1 });
    await db.collection('queue').createIndex({ ts: 1 });
    await db.collection('groups').createIndex({ id: 1 }, { unique: true });
    await db.collection('groups').createIndex({ members: 1 });
    await db.collection('pushSubs').createIndex({ nick: 1 });
    console.log('MongoDB connected');
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function hashPassword(password, saltHex) {
    return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100000, 64, 'sha512').toString('hex');
}

async function enqueue(nick, msg) {
    await db.collection('queue').insertOne({ recipient: nick, msg, ts: Date.now() });
}

async function flushQueue(nick) {
    const docs = await db.collection('queue').find({ recipient: nick }).sort({ ts: 1 }).toArray();
    if (docs.length) await db.collection('queue').deleteMany({ recipient: nick });
    return docs.map(d => d.msg);
}

async function sendPush(nick, payload) {
    const subs = await db.collection('pushSubs').find({ nick }).toArray();
    for (const sub of subs) {
        try {
            await webpush.sendNotification(sub.subscription, JSON.stringify(payload));
        } catch (err) {
            if (err.statusCode === 410 || err.statusCode === 404) {
                await db.collection('pushSubs').deleteOne({ _id: sub._id });
            }
        }
    }
}

async function deliverToGroup(groupId, msg, senderNick) {
    const group = await db.collection('groups').findOne({ id: groupId });
    if (!group) return;
    for (const member of group.members) {
        if (member === senderNick) continue;
        if (clients[member]) {
            clients[member].send(JSON.stringify(msg));
        } else {
            await enqueue(member, msg);
            if (msg.type === 'groupMessage') {
                const preview = msg.text ? msg.text.slice(0, 80) : '📎 Вложение';
                await sendPush(member, { title: group.name, body: senderNick + ': ' + preview, tag: groupId });
            }
        }
    }
}

// ── HTTP ─────────────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
    // VAPID public key для SW
    if (req.url === '/vapid-public-key') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(vapidPublicKey);
        return;
    }
    // Сохранение push-подписки
    if (req.url === '/push-subscribe' && req.method === 'POST') {
        let body = '';
        req.on('data', c => body += c);
        req.on('end', async () => {
            try {
                const { nick, subscription } = JSON.parse(body);
                if (!nick || !subscription) { res.writeHead(400); res.end(); return; }
                await db.collection('pushSubs').updateOne(
                    { nick, 'subscription.endpoint': subscription.endpoint },
                    { $set: { nick, subscription, ts: Date.now() } },
                    { upsert: true }
                );
                res.writeHead(200); res.end('ok');
            } catch (e) { console.error(e); res.writeHead(500); res.end(); }
        });
        return;
    }
    // Статика
    let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
    if (!filePath.startsWith(__dirname)) { res.writeHead(403); res.end(); return; }
    fs.readFile(filePath, (err, content) => {
        if (err) { res.writeHead(404); res.end('Not found'); return; }
        const ext = path.extname(filePath);
        const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
                       '.json': 'application/json', '.png': 'image/png', '.mp3': 'audio/mpeg',
                       '.webp': 'image/webp' };
        res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
        res.end(content);
    });
});

// ── WebSocket ────────────────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server, maxPayload: 20 * 1024 * 1024 });
let clients  = {};
let lastSeen = {};

function broadcastOnline() {
    const users = {};
    for (const n in clients) users[n] = true;
    const msg = JSON.stringify({ type: 'onlineList', users, lastSeen });
    for (const n in clients) clients[n].send(msg);
}

wss.on('connection', ws => {
    ws.authenticated = false;

    ws.on('message', async raw => {
        let data;
        try { data = JSON.parse(raw); } catch { return; }

        // ── register ───────────────────────────────────────────────────────
        if (data.type === 'register') {
            const nick = (data.nick || '').trim();
            const pwd  = data.password || '';
            if (!/^[a-zA-Z0-9_]{1,32}$/.test(nick)) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Ник: 1–32 символа, только a-z A-Z 0-9 _' })); return;
            }
            if (pwd.length < 6 || pwd.length > 128) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Пароль: 6–128 символов' })); return;
            }
            try {
                const salt = crypto.randomBytes(32).toString('hex');
                await db.collection('users').insertOne({ nick, hash: hashPassword(pwd, salt), salt });
            } catch (e) {
                if (e.code === 11000) {
                    ws.send(JSON.stringify({ type: 'authResult', success: false, error: 'Ник уже занят' })); return;
                }
                throw e;
            }
            ws.authenticated = true; ws.name = nick; clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: 'authResult', success: true, nick }));
            return;
        }

        // ── login ──────────────────────────────────────────────────────────
        if (data.type === 'login') {
            const nick = (data.nick || '').trim();
            const pwd  = data.password || '';
            const user = await db.collection('users').findOne({ nick });
            if (!user || hashPassword(pwd, user.salt) !== user.hash) {
                ws.send(JSON.stringify({ type: 'authResult', success: false, error: !user ? 'Неизвестный ник' : 'Неверный пароль' })); return;
            }
            if (clients[nick] && clients[nick] !== ws) {
                try { clients[nick].send(JSON.stringify({ type: 'kicked' })); clients[nick].close(); } catch {}
            }
            ws.authenticated = true; ws.name = nick; clients[nick] = ws;
            broadcastOnline();
            ws.send(JSON.stringify({ type: 'authResult', success: true, nick }));
            const pending = await flushQueue(nick);
            for (const m of pending) ws.send(JSON.stringify(m));
            const myGroups = {};
            const groups = await db.collection('groups').find({ members: nick }).toArray();
            for (const g of groups) { delete g._id; myGroups[g.id] = g; }
            if (Object.keys(myGroups).length)
                ws.send(JSON.stringify({ type: 'groupList', groups: myGroups }));
            return;
        }

        if (!ws.authenticated) return;

        // ── checkNick ──────────────────────────────────────────────────────
        if (data.type === 'checkNick') {
            const u = await db.collection('users').findOne({ nick: (data.nick || '').trim() }, { projection: { _id: 1 } });
            ws.send(JSON.stringify({ type: 'nickResult', nick: data.nick, exists: !!u }));
            return;
        }

        // ── message ────────────────────────────────────────────────────────
        if (data.type === 'message') {
            const u = await db.collection('users').findOne({ nick: data.to }, { projection: { _id: 1 } });
            if (!u) { ws.send(JSON.stringify({ type: 'deliveryError', to: data.to, error: 'no_user' })); return; }
            if (clients[data.to]) {
                clients[data.to].send(JSON.stringify(data));
            } else {
                await enqueue(data.to, data);
                const preview = data.text ? data.text.slice(0, 80) : '📎 Вложение';
                await sendPush(data.to, { title: ws.name, body: preview, tag: ws.name });
            }
            return;
        }

        // ── edit / delete / read / reaction ────────────────────────────────
        if (data.type === 'edit' || data.type === 'delete') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            else await enqueue(data.to, data);
            return;
        }
        if (data.type === 'read') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }
        if (data.type === 'reaction') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }

        // ── signal / typing ────────────────────────────────────────────────
        if (data.type === 'signal' || data.type === 'typing') {
            if (clients[data.to]) clients[data.to].send(JSON.stringify(data));
            return;
        }

        // ── createGroup ────────────────────────────────────────────────────
        if (data.type === 'createGroup') {
            const name = (data.name || '').trim();
            if (!name || name.length > 64) return;
            const members = [...new Set(Array.isArray(data.members) ? data.members : [])];
            if (!members.includes(ws.name)) members.push(ws.name);
            if (members.length < 2) return;
            for (const m of members) {
                const u = await db.collection('users').findOne({ nick: m }, { projection: { _id: 1 } });
                if (!u) return;
            }
            const id = 'g_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
            const group = { id, name, members, creator: ws.name };
            await db.collection('groups').insertOne(group);
            delete group._id;
            const notif = { type: 'groupCreated', group };
            for (const m of members) {
                if (clients[m]) clients[m].send(JSON.stringify(notif));
                else await enqueue(m, notif);
            }
            return;
        }

        // ── addGroupMember ─────────────────────────────────────────────────
        if (data.type === 'addGroupMember') {
            const nick = (data.nick || '').trim();
            if (!nick) return;
            const u = await db.collection('users').findOne({ nick }, { projection: { _id: 1 } });
            if (!u) { ws.send(JSON.stringify({ type: 'addMemberError', groupId: data.groupId, error: 'no_user' })); return; }
            const group = await db.collection('groups').findOne({ id: data.groupId });
            if (!group || !group.members.includes(ws.name)) return;
            if (group.members.includes(nick)) {
                ws.send(JSON.stringify({ type: 'addMemberError', groupId: data.groupId, error: 'already_member' })); return;
            }
            const newMembers = [...group.members, nick];
            await db.collection('groups').updateOne({ id: data.groupId }, { $set: { members: newMembers } });
            delete group._id;
            const updated = { ...group, members: newMembers };
            const notif = { type: 'groupMemberAdded', groupId: data.groupId, nick, group: updated };
            for (const m of newMembers) {
                if (clients[m]) clients[m].send(JSON.stringify(notif));
                else await enqueue(m, notif);
            }
            return;
        }

        // ── groupMessage / groupEdit / groupDelete / groupTyping / groupRead / groupReaction
        if (['groupMessage','groupEdit','groupDelete','groupTyping','groupRead','groupReaction'].includes(data.type)) {
            const group = await db.collection('groups').findOne({ id: data.groupId });
            if (!group || !group.members.includes(ws.name)) return;
            await deliverToGroup(data.groupId, data, ws.name);
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

// ── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
    server.listen(PORT, () => console.log('Server on port ' + PORT));
}).catch(err => { console.error('DB error:', err); process.exit(1); });
