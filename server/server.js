const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const db = require('./models/db');
const cryptoUtils = require('./utils/crypto');
const authRoutes = require('./routes/auth');
const chatRoutes = require('./routes/chat');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

app.use(cookieParser());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('client'));

// Routes
app.use('/auth', authRoutes);
app.use('/chat', chatRoutes);

app.set('socketIO', io);

io.on('connection', (socket) => {
    socket.on('register-user', (username) => {
        socket.join(username); // Join room named by username
        console.log(`${username} is online`);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});