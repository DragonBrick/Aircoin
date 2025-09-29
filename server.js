// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
require('dotenv').config();

const User = require('./models/User');
const Transaction = require('./models/Transaction');

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const ADMIN_PIN = '111'; // per your spec

// Connect to MongoDB
if (!MONGODB_URI) {
    console.error('MONGODB_URI missing in env. See .env.example');
    process.exit(1);
}

mongoose.connect(MONGODB_URI, {})
    .then(() => console.log('MongoDB connected'))
    .catch(err => { console.error('MongoDB connection error', err); process.exit(1); });

// Helpers
function createToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Missing auth' });
    const token = auth.split(' ')[1];
    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.user = await User.findOne({ userid: data.userid }).lean();
        if (!req.user) return res.status(401).json({ error: 'Invalid token user' });
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
    const { name, userid, password, pin } = req.body;
    if (!name || !userid || !password) return res.status(400).json({ error: 'Missing fields' });

    const existing = await User.findOne({ userid });
    if (existing) return res.status(400).json({ error: 'UserID already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const isAdmin = String(pin) === ADMIN_PIN;

    const user = new User({
        name,
        userid,
        passwordHash,
        isAdmin,
        balance: isAdmin ? 0 : 100 // regular users start with 100; admin has flag for infinite
    });

    await user.save();
    const token = createToken({ userid: user.userid });
    res.json({ ok: true, token, userid: user.userid, isAdmin: user.isAdmin });
});

// Login
app.post('/api/login', async (req, res) => {
    const { userid, password } = req.body;
    if (!userid || !password) return res.status(400).json({ error: 'Missing' });

    const user = await User.findOne({ userid });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = createToken({ userid: user.userid });
    res.json({ ok: true, token, userid: user.userid, isAdmin: user.isAdmin });
});

// Get balance & recent tx
app.get('/api/me', authMiddleware, async (req, res) => {
    const user = req.user;
    // For admin: show infinity
    const balance = user.isAdmin ? 'Infinity' : user.balance;
    // Recent txs involving user
    const txs = await Transaction.find({
        $or: [{ fromUserId: user.userid }, { toUserId: user.userid }]
    }).sort({ createdAt: -1 }).limit(50).lean();
    res.json({ userid: user.userid, name: user.name, isAdmin: user.isAdmin, balance, txs });
});

// Send AirCoin
app.post('/api/send', authMiddleware, async (req, res) => {
    const { toUserId, amount } = req.body;
    const sender = await User.findOne({ userid: req.user.userid });
    if (!toUserId || !amount || amount <= 0) return res.status(400).json({ error: 'Invalid to/amount' });

    const receiver = await User.findOne({ userid: toUserId });
    if (!receiver) return res.status(400).json({ error: 'Receiver not found' });

    // Admin has infinite funds: do not decrement admin balance
    if (!sender.isAdmin) {
        if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });
        sender.balance = Number((sender.balance - amount).toFixed(8));
        await sender.save();
    }

    // Credit receiver
    receiver.balance = Number((receiver.balance + amount).toFixed(8));
    await receiver.save();

    const tx = new Transaction({ fromUserId: sender.userid, toUserId: receiver.userid, amount });
    await tx.save();

    res.json({ ok: true, tx });
});

// Simple user list (for demo, not paginated)
app.get('/api/users', authMiddleware, async (req, res) => {
    const users = await User.find({}, { passwordHash: 0 }).lean();
    res.json(users);
});

app.listen(PORT, () => {
    console.log(`AirCoin app listening on port ${PORT}`);
});
