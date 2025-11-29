require('dotenv').config();
const db = require('./database.js');
const cors = require('cors');
const express = require('express');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

const {authenticateToken, authorizeRole} = require('./middleware/auth.js');

const app = express();
const port = process.env.PORT || 3500;

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.get('/status', (req, res) => {
    return res.json({ message: 'API is running' });
});

// === MOVIES ROUTES ===
app.get('/movies', (req, res) => {
    const sql = "SELECT * FROM movies ORDER BY id ASC";
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows);
    });
});

app.post('/movies', authenticateToken, (req, res) => {
    const { title, director, year } = req.body;
    const sql = 'INSERT INTO movies (title, director, year) VALUES (?, ?, ?)';
    db.run(sql, [title, director, year], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.status(201).json({ message: 'Film berhasil ditambahkan', movieId: this.lastID });
    });
});

app.put('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
    const { title, director, year } = req.body;
    const { id } = req.params;
    const sql = 'UPDATE movies SET title = ?, director = ?, year = ? WHERE id = ?';
    db.run(sql, [title, director, year, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.json({ message: 'Film berhasil diperbarui' });
    });
});

app.delete('/movies/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
    const { id } = req.params;
    const sql = 'DELETE FROM movies WHERE id = ?';
    db.run(sql, id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.json({ message: 'Film berhasil dihapus' });
    });
});

// === AUTH ROUTES ===
app.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || password.length < 6) {
        return res.status(400).json({ error: 'Username dan password (min 6 char) harus diisi' });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Error hashing:", err);
            return res.status(500).json({ error: 'Gagal memproses pendaftaran' });
        }

        const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        const params = [username.toLowerCase(), hashedPassword, 'user'];
        db.run(sql, params, function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint')) {
                    return res.status(409).json({ error: 'Username sudah digunakan' });
                }
                console.error("Error inserting user:", err);
                return res.status(500).json({ error: 'Gagal menyimpan pengguna' });
            }
            return res.status(201).json({ message: 'Registrasi berhasil', userId: this.lastID });
        });
    });
});

app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username dan password harus diisi' });
    }

    const sql = "SELECT * FROM users WHERE username = ?";
    db.get(sql, [username.toLowerCase()], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Kredensial tidak valid' });
        }

        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({ error: 'Kredensial tidak valid' });
            }

            const payload = { user: { id: user.id, username: user.username, role: user.role } };

            jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
                if (err) {
                    console.error("Error signing token:", err);
                    return res.status(500).json({ error: 'Gagal membuat token' });
                }
                return res.json({ message: 'Login berhasil', token });
            });
        });
    });
});

app.post('/auth/register-admin', (req, res) =>{
    const {username, password} = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({error: 'Gagal memproses pendaftaran'})
        
        const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
        const params = [username.toLowerCase(), hashedPassword, 'admin'];

        db.run(sql, params, function(err){
            if (err) return res.status(500).json({error: err.message});
            res.status(201).json({message: 'Admin berhasil dibuat', userId: this.lastID});
        });
    });
});

// === DIRECTORS ROUTES ===
app.get('/directors', (req, res) => {
    const sql = "SELECT * FROM directors ORDER BY id ASC";
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        return res.json(rows);
    });
});

app.post('/directors', authenticateToken, (req, res) => {
    const { name, birth_year } = req.body;
    const sql = "INSERT INTO directors (name, birth_year) VALUES (?, ?)";
    db.run(sql, [name, birth_year], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.status(201).json({ message: "Director berhasil ditambahkan", directorId: this.lastID });
    });
});

app.put('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
    const { name, birth_year } = req.body;
    const { id } = req.params;
    const sql = "UPDATE directors SET name = ?, birth_year = ? WHERE id = ?";
    db.run(sql, [name, birth_year, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.json({ message: "Director berhasil diperbarui" });
    });
});

app.delete('/directors/:id', [authenticateToken, authorizeRole('admin')], (req, res) => {
    const { id } = req.params;
    const sql = "DELETE FROM directors WHERE id = ?";
    db.run(sql, id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        return res.json({ message: "Director berhasil dihapus" });
    });
});

// === SERVER START ===
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});
