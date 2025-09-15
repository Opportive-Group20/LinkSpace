// =======================================================================
// FILE: server/index.js
// =======================================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp, FieldValue } = require('firebase-admin/firestore');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { customAlphabet } = require('nanoid');

// ==================== FIREBASE INITIALIZATION ====================
let serviceAccount;

if (process.env.GOOGLE_CREDENTIALS_JSON) {
    try {
        const decoded = Buffer.from(process.env.GOOGLE_CREDENTIALS_JSON, 'base64').toString('ascii');
        serviceAccount = JSON.parse(decoded);
        console.log("✅ Firebase credentials loaded from environment variable.");
    } catch (err) {
        console.error("❌ Failed to parse GOOGLE_CREDENTIALS_JSON.", err);
        process.exit(1);
    }
} else {
    const path = './serviceAccountKey.json';
    if (!fs.existsSync(path)) {
        console.error("❌ Firebase serviceAccountKey.json missing.");
        process.exit(1);
    }
    serviceAccount = require(path);
    console.log("✅ Firebase credentials loaded from local file.");
}

initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore();

// ==================== EXPRESS & CORS ====================
const app = express();
const server = http.createServer(app);

const allowedOrigins = [
    "http://localhost:3000",
    
    "https://linkspacez.netlify.app"
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error("CORS not allowed"));
    },
    methods: ["GET","POST","PUT","DELETE","OPTIONS"],
    credentials: true
}));
app.options("*", cors()); // handle preflight
app.use(express.json());

// ==================== JWT AUTH ====================
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_jwt_key_change_this';

const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Not authorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ message: 'Token invalid' });
    }
};

// ==================== SOCKET.IO ====================
const io = new Server(server, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET","POST"],
        credentials: true
    }
});

const userSockets = {};
const onlineUsers = new Set();

io.on('connection', socket => {
    console.log(`🔗 Connected: ${socket.id}`);

    socket.on('storeUserId', userId => {
        userSockets[userId] = socket.id;
        onlineUsers.add(userId);
        io.emit('onlineUsers', Array.from(onlineUsers));
    });

    socket.on('joinConversation', conversationId => {
        socket.join(conversationId);
    });

    socket.on('sendMessage', async ({ conversationId, senderId, text }) => {
        try {
            const userDoc = await db.collection('users').doc(senderId).get();
            const senderUsername = userDoc.exists ? userDoc.data().username : 'Unknown';

            const newMessage = { senderId, text, timestamp: Timestamp.now(), senderUsername };
            const conversationRef = db.collection('conversations').doc(conversationId);
            const messageRef = await conversationRef.collection('messages').add(newMessage);

            const conversationDoc = await conversationRef.get();
            const conversationData = conversationDoc.data();
            const updatePayload = { lastMessage: text, lastMessageTimestamp: newMessage.timestamp };

            conversationData.participants.forEach(pid => {
                if (pid !== senderId) updatePayload[`unreadCounts.${pid}`] = FieldValue.increment(1);
            });

            await conversationRef.update(updatePayload);

            const messageToSend = { id: messageRef.id, conversationId, ...newMessage };
            socket.broadcast.to(conversationId).emit('newMessage', messageToSend);

            // Notify users individually
            conversationData.participants.forEach(pid => {
                if (pid !== senderId) {
                    const sockId = userSockets[pid];
                    if (sockId) {
                        io.to(sockId).emit('updateUnreadCount', {
                            conversationId,
                            count: (conversationData.unreadCounts[pid] || 0) + 1
                        });
                    }
                }
            });
        } catch (err) {
            console.error("❌ Error sending message:", err);
        }
    });

    socket.on('disconnect', () => {
        for (const uid in userSockets) {
            if (userSockets[uid] === socket.id) {
                delete userSockets[uid];
                onlineUsers.delete(uid);
                io.emit('onlineUsers', Array.from(onlineUsers));
                break;
            }
        }
        console.log(`❌ Disconnected: ${socket.id}`);
    });
});

// ==================== ROUTES ====================
app.get('/', (req, res) => res.send("LinkSpace Server is running!"));

// --- Auth routes
app.post('/api/auth/register', require('./routes/register')(db, JWT_SECRET, customAlphabet, bcrypt, Timestamp));
app.post('/api/auth/login', require('./routes/login')(db, JWT_SECRET, bcrypt, Timestamp));
app.get('/api/auth/me', protect, require('./routes/me')(db));

// --- Friends & Groups routes
app.post('/api/friends/add', protect, require('./routes/friends')(db, userSockets, io, Timestamp, FieldValue));
app.post('/api/groups/create', protect, require('./routes/groupsCreate')(db, customAlphabet, Timestamp));
app.post('/api/groups/join', protect, require('./routes/groupsJoin')(db, userSockets, io, Timestamp, FieldValue));

// --- Conversations routes
app.post('/api/conversations/:id/read', protect, require('./routes/markRead')(db));
app.get('/api/conversations', protect, require('./routes/getConversations')(db));
app.get('/api/conversations/:id/messages', protect, require('./routes/getMessages')(db));

// ==================== START SERVER ====================
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
