const express = require('express');
const router = express.Router();
const db = require('../models/db');
const { encrypt, decrypt, computeSharedSecret } = require('../utils/crypto');
const ensureAuthenticated = require('../middleware/authMiddleware');

// Store pending handshakes in memory
// const activeSessions = {}; // In-memory key exchange storage { "sender-receiver": publicKey }

// Protect all chat routes
router.use(ensureAuthenticated);

router.post('/handshake', (req, res) => {
    const { sender, receiver, dhPublicKey, dhPublicKeyOther } = req.body;

    if (!sender || !receiver || !dhPublicKey) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    db.get(
        `SELECT * FROM handshakes WHERE user1 = ? AND user2 = ?`,
        [sender, receiver],
        (err, row) => {
            if (err) return res.status(500).send(err.message);

            if (!row) {
                // No existing handshake — store in pending_handshakes
                db.run(
                    `INSERT INTO pending_handshakes (sender, receiver, dhPublicKey)
                     VALUES (?, ?, ?)`,
                    [sender, receiver, dhPublicKey],
                    function (err) {
                        if (err) return res.status(500).send(err.message);
                        res.json({ status: 'Pending handshake created' });
                    }
                );
            } else {
                // Existing handshake — update accordingly
                const query = dhPublicKeyOther
                    ? `UPDATE handshakes SET dhPublicKeyUser2 = ? WHERE user1 = ? AND user2 = ?`
                    : `UPDATE handshakes SET dhPublicKeyUser1 = ? WHERE user1 = ? AND user2 = ?`;

                const params = dhPublicKeyOther
                    ? [dhPublicKeyOther, sender, receiver]
                    : [dhPublicKey, sender, receiver];

                db.run(query, params, function (err) {
                    if (err) return res.status(500).send(err.message);
                    res.json({ status: 'Handshake updated' });
                });
            }
        }
    );

    const keyId = `${sender}-${receiver}`;
    // activeSessions[keyId] = dhPublicKey;

    console.log(`Stored DH public key for ${keyId}`);
    // res.status(200).json({ success: true });
});

router.get('/complete-pending-handshakes/:username', (req, res) => {
    const { username } = req.params;

    db.all(
        `SELECT * FROM pending_handshakes WHERE receiver = ?`,
        [username],
        async (err, rows) => {
            if (err) return res.status(500).send(err.message);
            if (!rows.length) return res.json({ status: 'No pending handshakes' });

            const results = [];

            for (const row of rows) {
                const myKeys = generateECDHKeys(); // Server-side DH key generation

                // Save mutual handshake
                await new Promise((resolve, reject) => {
                    db.run(
                        `INSERT INTO handshakes (
              user1, user2, dhPublicKeyUser1, dhPublicKeyUser2
            ) VALUES (?, ?, ?, ?)`,
                        [row.sender, row.receiver, row.dhPublicKey, myKeys.publicKey],
                        function (err) {
                            if (err) return reject(err);
                            resolve();
                        }
                    );
                });

                // Delete pending request
                await new Promise((resolve, reject) => {
                    db.run(
                        `DELETE FROM pending_handshakes WHERE id = ?`,
                        [row.id],
                        function (err) {
                            if (err) return reject(err);
                            resolve();
                        }
                    );
                });

                results.push({
                    contact: row.sender,
                    publicKeySent: myKeys.publicKey
                });
            }

            res.json({ completed: results });
        }
    );
});

router.get('/get-handshake/:from/:to', (req, res) => {
    const { from, to } = req.params;
    // const keyId = `${from}-${to}`;
    // const publicKey = activeSessions[keyId];

    const publicKey = db.get(
        `SELECT * FROM handshakes WHERE user1 = ? AND user2 = ? ORDER BY createdAt DESC LIMIT 1`,
        [from, to],
        (err, row) => {

            if (err || !row) {
                return res.status(404).send({ error: "Handshake not found" });
            }

            res.json(row);
        }
    );
});

// Send message (store in DB)
router.post('/send', (req, res) => {
    const { sender, receiver, plaintext, sharedKey } = req.body;

    const aesKey = sharedKey.slice(0, 32);
    const encrypted = encrypt(plaintext, aesKey);

    db.run(
        `INSERT INTO messages (sender, receiver, iv, tag, ciphertext)
         VALUES (?, ?, ?, ?, ?)`,
        [sender, receiver, encrypted.iv, encrypted.tag, encrypted.ciphertext],
        function (err) {
            if (err) return res.status(500).send(err.message);
            // Emit only if receiver is online
            const io = req.app.get('socketIO');
            if (io.sockets.adapter.rooms.has(receiver)) {
                io.to(receiver).emit('new-message', {
                    sender,
                    receiver,
                    ...encrypted
                });
            }
            res.sendStatus(200);
        }
    );
});

// Fetch all messages between two users
router.get('/messages/:withUser', (req, res) => {
    const currentUser = req.session.user.username;
    const withUser = req.params.withUser;
    const sharedKey = req.query.key; // passed from client after handshake

    db.all(
        `SELECT * FROM messages WHERE
     (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
     ORDER BY timestamp ASC`,
        [currentUser, withUser, withUser, currentUser],
        (err, rows) => {
            if (err) return res.status(500).send(err.message);

            const decrypted = rows.map((msg) => {
                try {
                    return {
                        ...msg,
                        plaintext: decrypt(msg, sharedKey.slice(0, 32))
                    };
                } catch (e) {
                    console.error("Decryption failed:", e);
                    return null;
                }
            }).filter(Boolean);

            res.json(decrypted);
        }
    );
});

module.exports = router;