const express = require('express');
const authRoutes = require('./routes/authRoutes');  // Mengimpor rute autentikasi
const todoRoutes = require('./routes/todosdb.js');
const app = express();

app.use('/', authRoutes);  // Semua rute dalam authRoutes.js akan diakses di bawah path '/'
app.use('/todos', todoRoutes);  // Semua rute dalam todosdb.js akan diakses di bawah path '/todos'

require('dotenv').config();
const port = process.env.PORT;
const expressLayout = require('express-ejs-layouts')
const db = require('./database/db')

const session = require('express-session');
const {isAuthenticated} = require('./middlewares/middleware.js');

const path = require('path');

// Setup session middleware
app.use(session({
    secret: 'your-secret-key',  // Gantilah dengan kunci yang lebih aman
    resave: false,
    saveUninitialized: true,
}));

app.use(express.static('public'));

// Middleware untuk melayani file statis
app.use(express.static(path.join(__dirname, 'public')));

// Middleware untuk menambahkan `user` ke res.locals
app.use((req, res, next) => {
    // Pastikan `user` ada dalam session, jika tidak, beri nilai null
    res.locals.user = req.session.userId || null;  // userId disimpan di session saat login
    next();
});

app.use(expressLayout);
app.use(express.json());

app.use('/todos', todoRoutes);
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));

// Konfigurasi express-session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set ke true jika menggunakan HTTPS
}));

app.use('/', authRoutes);

app.get('/', isAuthenticated, (req, res) => {
    res.render('index', {
        layout: 'layouts/main-layout'
    });
});

app.get('/contact', isAuthenticated, (req, res) => {
    res.render('contact', {
        layout: 'layouts/main-layout'
    });
});

app.get('/todo-view', isAuthenticated, (req, res) => {
    db.query('SELECT * FROM todos', (err, todos) => {
        if (err) return res.status(500).send('Internal Server Error');
        res.render('todo', {
            layout: 'layouts/main-layout',
            todos: todos
        });
    });
});

app.use((req, res) => {
    res.status(404).send('404 - Page Not Found');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});