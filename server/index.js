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

let serviceAccount;
if (process.env.GOOGLE_CREDENTIALS_JSON) {
    try {
        const decodedCredentials = Buffer.from(process.env.GOOGLE_CREDENTIALS_JSON, 'base64').toString('ascii');
        serviceAccount = JSON.parse(decodedCredentials);
        console.log("Successfully parsed Firebase credentials from environment variable.");
    } catch (e) {
        console.error("FATAL ERROR: Could not parse GOOGLE_CREDENTIALS_JSON from Base64.", e);
        process.exit(1);
    }
} else {
    const serviceAccountPath = './serviceAccountKey.json';
    if (!fs.existsSync(serviceAccountPath)) {
        console.error("FATAL ERROR: Firebase serviceAccountKey.json not found for local development.");
        process.exit(1);
    }
    serviceAccount = require(serviceAccountPath);
    console.log("Successfully loaded Firebase credentials from local file.");
}

initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore();
const app = express();
const server = http.createServer(app);

const allowedOrigins = [
  "http://localhost:3000",
  "https://linkspacez.netlify.app"   // your Netlify frontend
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // ✅ handle preflight

app.use(express.json());
const JWT_SECRET = 'B4D7F9A2E1C8G3H6J9K2M5N8PQR4T7W9Z$C&F)J@NcRfUjXn2r5u8x/A%D*G-KaPdSgVkY';
const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Not authorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token failed' });
    }
};

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  }
});
const userSockets = {};
const onlineUsers = new Set();

io.on('connection', (socket) => {
    console.log(`✅ User Connected: ${socket.id}`);
    socket.on('storeUserId', (userId) => {
        userSockets[userId] = socket.id;
        onlineUsers.add(userId);
        io.emit('onlineUsers', Array.from(onlineUsers));
    });
    socket.on('joinConversation', (conversationId) => {
        socket.join(conversationId);
    });
    socket.on('sendMessage', async ({ conversationId, senderId, text }) => {
        try {
            const userDoc = await db.collection('users').doc(senderId).get();
            const senderUsername = userDoc.exists ? userDoc.data().username : 'Unknown User';
            const newMessage = { senderId, text, timestamp: Timestamp.now(), senderUsername };
            const conversationRef = db.collection('conversations').doc(conversationId);
            const messageRef = await conversationRef.collection('messages').add(newMessage);
            const conversationDoc = await conversationRef.get();
            const conversationData = conversationDoc.data();
            const updatePayload = { lastMessage: text, lastMessageTimestamp: newMessage.timestamp };
            conversationData.participants.forEach(participantId => {
                if (participantId !== senderId) {
                    updatePayload[`unreadCounts.${participantId}`] = FieldValue.increment(1);
                }
            });
            await conversationRef.update(updatePayload);
            const messageToSend = { id: messageRef.id, conversationId, ...newMessage };
            socket.broadcast.to(conversationId).emit('newMessage', messageToSend);
            conversationData.participants.forEach(participantId => {
                if (participantId !== senderId) {
                    const recipientSocketId = userSockets[participantId];
                    if (recipientSocketId) {
                        io.to(recipientSocketId).emit('updateUnreadCount', {
                            conversationId,
                            count: (conversationData.unreadCounts[participantId] || 0) + 1
                        });
                    }
                }
            });
        } catch (error) {
            console.error("Error sending message:", error);
        }
    });
    socket.on('disconnect', () => {
        for (const userId in userSockets) {
            if (userSockets[userId] === socket.id) {
                delete userSockets[userId];
                onlineUsers.delete(userId);
                io.emit('onlineUsers', Array.from(onlineUsers));
                break;
            }
        }
        console.log(`❌ User Disconnected: ${socket.id}`);
    });
});

app.get("/", (req, res) => {
    res.send("LinkSpace Server is running!");
});
app.get('/api/auth/me', protect, async (req, res) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.id).get();
        if (!userDoc.exists) return res.status(404).json({ message: 'User not found' });
        const userData = userDoc.data();
        res.json({ id: userDoc.id, username: userData.username, email: userData.email, inviteCode: userData.inviteCode });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: 'Please enter all fields' });
    try {
        const usersRef = db.collection('users');
        const emailSnapshot = await usersRef.where('email', '==', email).get();
        if (!emailSnapshot.empty) return res.status(400).json({ message: 'User with this email already exists' });
        const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8);
        let inviteCode;
        let codeExists = true;
        while (codeExists) {
            const tempCode = nanoid();
            inviteCode = `${tempCode.slice(0, 4)}-${tempCode.slice(4)}`;
            const codeSnapshot = await usersRef.where('inviteCode', '==', inviteCode).get();
            if (codeSnapshot.empty) codeExists = false;
        }
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const newUserRef = await usersRef.add({ username, email, passwordHash, inviteCode, createdAt: Timestamp.now() });
        const token = jwt.sign({ id: newUserRef.id, email }, JWT_SECRET, { expiresIn: '30d' });
        res.status(201).json({ token, user: { id: newUserRef.id, username, email, inviteCode } });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const usersRef = db.collection('users');
        const snapshot = await usersRef.where('email', '==', email).limit(1).get();
        if (snapshot.empty) return res.status(400).json({ message: 'Invalid credentials' });
        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();
        const isMatch = await bcrypt.compare(password, userData.passwordHash);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: userDoc.id, email: userData.email }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: userDoc.id, username: userData.username, email: userData.email, inviteCode: userData.inviteCode } });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/friends/add', protect, async (req, res) => {
    const { inviteCode } = req.body;
    const currentUserId = req.user.id;
    if (!inviteCode) return res.status(400).json({ message: 'Invite code is required' });
    try {
        const usersRef = db.collection('users');
        const friendSnapshot = await usersRef.where('inviteCode', '==', inviteCode.toUpperCase()).limit(1).get();
        if (friendSnapshot.empty) return res.status(404).json({ message: 'User with this invite code not found' });
        const friendDoc = friendSnapshot.docs[0];
        const friendId = friendDoc.id;
        const friendData = friendDoc.data();
        if (friendId === currentUserId) return res.status(400).json({ message: "You can't add yourself" });
        const conversationsRef = db.collection('conversations');
        const q1 = await conversationsRef.where('participants', '==', [currentUserId, friendId]).get();
        const q2 = await conversationsRef.where('participants', '==', [friendId, currentUserId]).get();
        if (!q1.empty || !q2.empty) return res.status(400).json({ message: 'You are already friends' });
        const newConversationData = { type: 'private', participants: [currentUserId, friendId], createdAt: Timestamp.now(), lastMessage: 'You are now connected!', lastMessageTimestamp: Timestamp.now(), unreadCounts: { [currentUserId]: 0, [friendId]: 1 } };
        const newConversationRef = await conversationsRef.add(newConversationData);
        const currentUserDoc = await db.collection('users').doc(currentUserId).get();
        const currentUserData = currentUserDoc.data();
        const friendSocketId = userSockets[friendId];
        if (friendSocketId) {
            io.to(friendSocketId).emit('newConversation', { id: newConversationRef.id, ...newConversationData, name: currentUserData.username, avatar: `https://placehold.co/100x100/f59e0b/ffffff?text=${currentUserData.username.charAt(0).toUpperCase()}` });
        }
        res.status(201).json({ message: 'Friend added successfully!', conversation: { id: newConversationRef.id, ...newConversationData, name: friendData.username, avatar: `https://placehold.co/100x100/6366f1/ffffff?text=${friendData.username.charAt(0).toUpperCase()}` } });
    } catch (error) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/groups/create', protect, async (req, res) => {
    const { name } = req.body;
    const creatorId = req.user.id;
    if (!name) return res.status(400).json({ message: 'Group name is required' });
    try {
        const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8);
        const inviteCode = `${nanoid().slice(0, 4)}-${nanoid().slice(4, 8)}`;
        const creatorDoc = await db.collection('users').doc(creatorId).get();
        const creatorUsername = creatorDoc.exists ? creatorDoc.data().username : 'A user';
        const newGroupData = { name, type: 'group', participants: [creatorId], admins: [creatorId], inviteCode, createdAt: Timestamp.now(), lastMessage: `Group created by ${creatorUsername}`, lastMessageTimestamp: Timestamp.now(), unreadCounts: { [creatorId]: 0 } };
        const newGroupRef = await db.collection('conversations').add(newGroupData);
        res.status(201).json({ message: 'Group created successfully!', conversation: { id: newGroupRef.id, ...newGroupData, avatar: `https://placehold.co/100x100/10b981/ffffff?text=${name.charAt(0).toUpperCase()}` } });
    } catch (error) {
        res.status(500).json({ message: 'Server error while creating group' });
    }
});
app.post('/api/groups/join', protect, async (req, res) => {
    const { inviteCode } = req.body;
    const userId = req.user.id;
    if (!inviteCode) return res.status(400).json({ message: 'Invite code is required' });
    try {
        const conversationsRef = db.collection('conversations');
        const groupSnapshot = await conversationsRef.where('inviteCode', '==', inviteCode.toUpperCase()).limit(1).get();
        if (groupSnapshot.empty) return res.status(404).json({ message: 'Group with this invite code not found' });
        const groupDoc = groupSnapshot.docs[0];
        const groupId = groupDoc.id;
        const groupData = groupDoc.data();
        if (groupData.participants.includes(userId)) {
            return res.status(400).json({ message: 'You are already in this group' });
        }
        await conversationsRef.doc(groupId).update({
            participants: FieldValue.arrayUnion(userId),
            [`unreadCounts.${userId}`]: 0
        });
        const userDoc = await db.collection('users').doc(userId).get();
        const username = userDoc.exists ? userDoc.data().username : 'A new user';
        const joinMessage = `${username} has joined the group.`;
        await conversationsRef.doc(groupId).collection('messages').add({ senderId: 'system', text: joinMessage, timestamp: Timestamp.now() });
        await conversationsRef.doc(groupId).update({ lastMessage: joinMessage, lastMessageTimestamp: Timestamp.now() });
        groupData.participants.forEach(participantId => {
            const socketId = userSockets[participantId];
            if (socketId) {
                io.to(socketId).emit('userJoinedGroup', { groupId, newParticipantId: userId, newParticipantUsername: username });
            }
        });
        res.status(200).json({ message: 'Joined group successfully!', conversation: { ...groupData, id: groupId, participants: [...groupData.participants, userId], avatar: `https://placehold.co/100x100/10b981/ffffff?text=${groupData.name.charAt(0).toUpperCase()}` } });
    } catch (error) {
        res.status(500).json({ message: 'Server error while joining group' });
    }
});
app.post('/api/conversations/:id/read', protect, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const conversationRef = db.collection('conversations').doc(id);
        await conversationRef.update({ [`unreadCounts.${userId}`]: 0 });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Failed to mark as read' });
    }
});
app.get('/api/conversations', protect, async (req, res) => {
    try {
        const snapshot = await db.collection('conversations').where('participants', 'array-contains', req.user.id).orderBy('lastMessageTimestamp', 'desc').get();
        const conversations = await Promise.all(snapshot.docs.map(async doc => {
            const data = doc.data();
            let name = data.name;
            let avatar;
            let otherParticipantId = null;
            if (data.type === 'private') {
                otherParticipantId = data.participants.find(p => p !== req.user.id);
                if (otherParticipantId) {
                    const userDoc = await db.collection('users').doc(otherParticipantId).get();
                    if (userDoc.exists) {
                        name = userDoc.data().username;
                        avatar = `https://placehold.co/100x100/6366f1/ffffff?text=${name.charAt(0).toUpperCase()}`;
                    }
                }
            } else {
                avatar = `https://placehold.co/100x100/10b981/ffffff?text=${name.charAt(0).toUpperCase()}`;
            }
            return { id: doc.id, ...data, name, avatar, otherParticipantId };
        }));
        res.json(conversations);
    } catch (error) { res.status(500).json({ message: 'Failed to fetch conversations' }); }
});
app.get('/api/conversations/:id/messages', protect, async (req, res) => {
    try {
        const { id } = req.params;
        const conversationRef = db.collection('conversations').doc(id);
        const conversationDoc = await conversationRef.get();
        if (!conversationDoc.exists || !conversationDoc.data().participants.includes(req.user.id)) return res.status(403).json({ message: 'Not authorized' });
        const messagesSnapshot = await conversationRef.collection('messages').orderBy('timestamp', 'asc').get();
        const messages = messagesSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json(messages);
    } catch (error) { res.status(500).json({ message: 'Failed to fetch messages' }); }
});

// --- 5. SERVER START ---
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
