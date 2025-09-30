// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    userid: { type: String, required: true, unique: true }, // chosen id
    passwordHash: { type: String, required: true },
    balance: { type: Number, default: 100 }, // start with 100 AirCoin
    isAdmin: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
