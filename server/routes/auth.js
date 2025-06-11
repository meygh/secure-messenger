const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { generateRSAKeyPair } = require('../utils/crypto');

// Register route
router.post('/register', (req, res) => {
    const { username } = req.body;
    const { publicKey, privateKey } = generateRSAKeyPair(); // Save both

    console.log('User: ', username, publicKey);

    db.run(
        'INSERT INTO users (username, publicKey) VALUES (?, ?)',
        [username, publicKey],
        function (err) {
            if (err) return res.status(500).send(err.message);
            res.json({ username, publicKey });
        }
    );
});

// Login route
router.post('/login', (req, res) => {
    const { username } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(400).send('User not found');
        req.session.user = {
            username: user.username,
            publicKey: user.publicKey
        };
        res.redirect('/chat.html');
    });
});

// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send('Logout failed');
        res.redirect('/');
    });
});

router.get('/user', (req, res) => {
    if (req.session.user) {
        res.json({ authenticated: true, user: req.session.user });
    } else {
        res.json({ authenticated: false });
    }
});

router.get('/get-private-key/:username', (req, res) => {
    const { username } = req.params;

    db.get('SELECT privateKey FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) return res.status(404).send('Private key not found');
        res.json({ privateKey: row.privateKey });
    });
});

module.exports = router;