let socket = null;

let currentUser = '';
let currentContact = '';
let myRSAKeys = null;
let myECDHKeys = null;
let sharedKey = null;

function waitForSodium() {
    return new Promise((resolve) => {
        const check = () => {
            if (window.sodium && sodium.ready) {
                sodium = window.sodium;
                sodium.ready.then(resolve);
            } else {
                setTimeout(check, 50);
            }
        };
        check();
    });
}

// Handle register form
document.addEventListener('DOMContentLoaded', async () => {
    await waitForSodium();
    loadCurrentUser();
    connectSocket();

    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const res = await fetch('/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });
            const data = await res.json();
            alert(`Registered as ${username}`);
            localStorage.setItem('user', JSON.stringify({
                username,
                publicKey: data.publicKey,
                privateKey: data.privateKey
            }));
        });
    }

    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            localStorage.setItem('loggedInUser', username);
            alert(`Logged in as ${username}`);
        });
    }
});

async function connectSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log("Connected to server");
        socket.emit('register-user', currentUser); // Tell server who we are
    });

    socket.on('new-message', (msg) => {
        if (
            (msg.sender === currentUser && msg.receiver === currentContact) ||
            (msg.receiver === currentUser && msg.sender === currentContact)
        ) {
            const decrypted = decryptMessage(msg, sharedKey.slice(0, 32));
            displayMessage(`${msg.sender}: ${decrypted}`);
        }
    });

    socket.on('disconnect', () => {
        console.log("Disconnected from server");
    });
}

async function loadCurrentUser() {
    const res = await fetch('/auth/user');
    const data = await res.json();

    if (!data.authenticated) {
        // alert("You must be logged in.");
        window.location.href = '/login.html';
        return;
    }

    currentUser = data.user.username;

    // Check localStorage for private key
    let privateKey = localStorage.getItem(`privateKey-${currentUser}`);

    if (!privateKey) {
        // Request public key from server
        const res = await fetch(`/auth/get-private-key/${currentUser}`);
        const data = await res.json();
        privateKey = data.privateKey; // Sent only during login
        localStorage.setItem(`privateKey-${currentUser}`, privateKey);
    }
}

// Generate X25519 key pair
function generateECDHKeys() {
    if (!sodium) throw new Error("LibSodium is not initialized");

    const kp = sodium.crypto_box_keypair(); // returns { keyType, publicKey, privateKey }

    return {
        publicKey: sodium.to_hex(kp.publicKey),
        privateKey: sodium.to_hex(kp.privateKey)
    };
}

// Utility: Convert Uint8Array to hex string
function arrayToHex(buffer) {
    return [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
}

// Utility: Convert hex string to Uint8Array
function hexToArray(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        throw new TypeError('Invalid hex string');
    }

    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return arr;
}

function hexToArrayBuffer(hex) {
    const buffer = new ArrayBuffer(hex.length / 2);
    const dataView = new Uint8Array(buffer);
    for (let i = 0; i < hex.length; i += 2) {
        dataView[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return buffer;
}

function strToArrayBuffer(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function computeSharedSecret(privateKeyHex, publicKeyHex) {
    const sk = hexToArray(privateKeyHex);
    const pk = hexToArray(publicKeyHex);

    const sharedKey = sodium.crypto_scalarmult(sk, pk);
    return arrayToHex(sharedKey); // Hex-encoded shared secret
}

async function selectContact() {
    currentContact = document.getElementById('contact').value.trim();
    if (!currentContact || !currentUser) {
        alert("Please enter a contact.");
        return;
    }

    // Load stored handshake
    const keyRes = await fetch(`/chat/handshake/${currentUser}/${currentContact}`);
    const keyData = await keyRes.json().catch(() => null);

    let theirPublicKey = keyData?.dhPublicKeyUser1 || null;

    if (!theirPublicKey) {
        alert("No public key found yet. Try again later.");
        return;
    }

    // Compute shared secret
    const myKeys = {
        privateKey: localStorage.getItem(`sk-${currentUser}-${currentContact}`)
    };

    const sharedSecret = computeSharedSecret(myKeys.privateKey, theirPublicKey);
    localStorage.setItem(`sharedKey-${currentUser}-${currentContact}`, sharedSecret);

    // Load and decrypt messages
    const messagesRes = await fetch(`/chat/messages/${currentContact}?key=${sharedSecret}`);
    const messages = await messagesRes.json();

    document.getElementById('chat').innerHTML = '';
    messages.forEach((msg) => {
        try {
            const decrypted = decryptMessage(msg, sharedSecret);
            displayMessage(`${msg.sender}: ${decrypted}`);
        } catch (e) {
            console.error("Failed to decrypt message:", e);
        }
    });

    // alert(`You're now chatting with ${currentContact}.`);
}

async function encryptWithPublicKey(plaintext, pemPublicKey) {
    const encoder = new TextEncoder();
    const binaryData = encoder.encode(plaintext);

    // Convert PEM to CryptoKey
    const publicKey = await importPublicKey(pemPublicKey);

    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        binaryData
    );

    return {
        ciphertext: arrayToHex(encryptedBuffer)
    };
}

async function importPublicKey(pem) {
    const binaryDerString = window.atob(pem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, ''));

    const binaryDer = strToArrayBuffer(binaryDerString);

    return await window.crypto.subtle.importKey(
        "spki",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

async function decryptWithPrivateKey(cipherObj) {
    const decoder = new TextDecoder();
    const privateKeyPem = localStorage.getItem(`privateKey-${currentUser}`);
    const privateKey = await importPrivateKey(privateKeyPem);

    const cipherBuffer = hexToArrayBuffer(cipherObj.ciphertext);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        cipherBuffer
    );

    return decoder.decode(decryptedBuffer);
}

async function importPrivateKey(pem) {
    const binaryDerString = window.atob(pem
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s/g, ''));

    const binaryDer = strToArrayBuffer(binaryDerString);

    return await window.crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"]
    );
}

async function sendMessage() {
    const contact = document.getElementById('contact').value.trim();
    const text = document.getElementById('message').value.trim();

    if (!contact || !text || !currentUser) return;

    // Get recipient's public key
    const res = await fetch(`/auth/get-public-key/${contact}`);
    const data = await res.json();
    const publicKey = data.publicKey;

    // Encrypt with RSA public key
    const encrypted = await encryptWithPublicKey(text, publicKey);

    // Send to backend
    const sendRes = await fetch('/chat/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            sender: currentUser,
            receiver: contact,
            ...encrypted
        })
    });

    if (sendRes.ok) {
        displayMessage(`You: ${text}`);
        document.getElementById('message').value = '';
    }
}

socket.on('new-message', async (msg) => {
    if (
        (msg.sender === currentUser && msg.receiver === currentContact) ||
        (msg.receiver === currentUser && msg.sender === currentContact)
    ) {
        const aesKey = sharedKey.slice(0, 32);
        try {
            const decrypted = await decryptMessage(msg, aesKey);
            displayMessage(`${msg.sender}: ${decrypted}`);
        } catch (e) {
            console.error("Failed to decrypt message:", e);
        }
    }
});

function displayMessage(text) {
    const chatBox = document.getElementById('chat');
    chatBox.innerHTML += `<div class="message">${text}</div>`;
    chatBox.scrollTop = chatBox.scrollHeight;
}