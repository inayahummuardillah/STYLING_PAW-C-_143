// File: routes/authRoutes.js
const express = require('express');
const router = express.Router();
const db = require('../database/db');  // Pastikan db sudah terkonfigurasi dengan benar
const bcrypt = require('bcrypt');
module.exports = router;

// Sign In route (POST)
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Cek user dari database
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Internal Server Error');

        if (results.length === 0) {
            return res.status(401).send('Username tidak ditemukan');
        }

        const user = results[0];

        // Bandingkan password dengan bcrypt
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send('Terjadi kesalahan saat verifikasi password');
            if (!isMatch) return res.status(401).send('Password salah');

            // Jika cocok, simpan data user di session
            req.session.userId = user.id;
            req.session.username = user.username;

            res.redirect('/'); // Redirect ke halaman utama setelah login sukses
        });
    });
});

// Register route (POST)
router.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Hash password dengan bcrypt
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).send('Terjadi kesalahan saat mengenkripsi password');

        // Simpan user baru ke database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
            if (err) return res.status(500).send('Terjadi kesalahan saat pendaftaran');

            res.redirect('/login'); // Redirect ke halaman login setelah registrasi sukses
        });
    });
});

module.exports = router;
