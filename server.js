require("dotenv").config();
const express = require("express");
const cors = require("cors");
const db = require("./db.js"); // menggunakan modul pg baru
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticateToken, authorizeRole } = require("./middleware/auth.js");

const app = express();
const PORT = process.env.PORT || 3300;
const JWT_SECRET = process.env.JWT_SECRET;

// === MIDDLEWARE ===
app.use(cors());
app.use(express.json());

// === ROUTES ===

// STATUS
app.get("/status", (req, res) => {
  res.json({ ok: true, service: "film-api" });
});

// === AUTH ROUTES ===

// REGISTER USER
app.post("/auth/register", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 6) {
    return res.status(400).json({
      error: "Username dan password (min 6 char) harus diisi",
    });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "user",
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

// REGISTER ADMIN
app.post("/auth/register-admin", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || password.length < 6) {
    return res.status(400).json({
      error: "Username dan password (min 6 char) harus diisi",
    });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const sql =
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username";
    const result = await db.query(sql, [
      username.toLowerCase(),
      hashedPassword,
      "admin",
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username sudah digunakan" });
    }
    next(err);
  }
});

// LOGIN
app.post("/auth/login", async (req, res, next) => {
  const { username, password } = req.body;

  try {
    const sql = "SELECT * FROM users WHERE username = $1";
    const result = await db.query(sql, [username.toLowerCase()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Kredensial tidak valid" });
    }

    const payload = {
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    res.json({ message: "Login berhasil", token: token });
  } catch (err) {
    next(err);
  }
});

// === MOVIE ROUTES ===

// GET ALL MOVIES
app.get("/movies", async (req, res, next) => {
  const sql = `
    SELECT m.id, m.title, m.year,
           d.id AS director_id, d.name AS director_name
    FROM movies m
    LEFT JOIN directors d ON m.director_id = d.id
    ORDER BY m.id ASC
  `;

  try {
    const result = await db.query(sql);
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// GET MOVIE BY ID
app.get("/movies/:id", async (req, res, next) => {
  const sql = `
    SELECT m.id, m.title, m.year,
           d.id AS director_id, d.name AS director_name
    FROM movies m
    LEFT JOIN directors d ON m.director_id = d.id
    WHERE m.id = $1
  `;

  try {
    const result = await db.query(sql, [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Film tidak ditemukan" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// CREATE MOVIE
app.post("/movies", authenticateToken, async (req, res, next) => {
  const { title, director_id, year } = req.body;

  if (!title || !director_id || !year) {
    return res.status(400).json({
      error: "title, director_id, year wajib diisi",
    });
  }

  const sql = `INSERT INTO movies (title, director_id, year)
               VALUES ($1, $2, $3) RETURNING *`;

  try {
    const result = await db.query(sql, [title, director_id, year]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// UPDATE MOVIE
app.put(
  "/movies/:id",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const { title, director_id, year } = req.body;

    const sql = `
      UPDATE movies
      SET title = $1, director_id = $2, year = $3
      WHERE id = $4
      RETURNING *
    `;

    try {
      const result = await db.query(sql, [
        title,
        director_id,
        year,
        req.params.id,
      ]);

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Film tidak ditemukan" });
      }

      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

// DELETE MOVIE
app.delete(
  "/movies/:id",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const sql = "DELETE FROM movies WHERE id = $1 RETURNING *";

    try {
      const result = await db.query(sql, [req.params.id]);

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Film tidak ditemukan" });
      }

      res.status(204).send();
    } catch (err) {
      next(err);
    }
  }
);

// === DIRECTOR ROUTES ===
// (Tugas praktikum - membuat sendiri semua CRUD dengan pola di atas)

// === DIRECTOR ROUTES ===

// GET ALL DIRECTORS
app.get("/directors", async (req, res, next) => {
  const sql = `
    SELECT id, name, birthyear
    FROM directors
    ORDER BY id ASC
  `;

  try {
    const result = await db.query(sql);
    res.json(result.rows); // birthyear pasti ada karena NOT NULL di DB
  } catch (err) {
    next(err);
  }
});

// GET DIRECTOR BY ID
app.get("/directors/:id", async (req, res, next) => {
  const sql = `
    SELECT id, name, birthyear
    FROM directors
    WHERE id = $1
  `;

  try {
    const result = await db.query(sql, [req.params.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Director tidak ditemukan" });
    }

    res.json(result.rows[0]); // birthyear pasti ada
  } catch (err) {
    next(err);
  }
});

// CREATE DIRECTOR
app.post("/directors", authenticateToken, async (req, res, next) => {
  const { name, birthYear } = req.body;

  if (!name) {
    return res.status(400).json({ error: "name wajib diisi" });
  }
  if (birthYear === undefined || birthYear === null) {
    return res.status(400).json({ error: "birthYear wajib diisi" });
  }

  const sql = `
    INSERT INTO directors (name, birthyear)
    VALUES ($1, $2)
    RETURNING *
  `;

  try {
    const result = await db.query(sql, [name, birthYear]);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// UPDATE DIRECTOR (ADMIN ONLY)
app.put(
  "/directors/:id",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const { name, birthYear } = req.body;

    if (!name) {
      return res.status(400).json({ error: "name wajib diisi" });
    }
    if (birthYear === undefined || birthYear === null) {
      return res.status(400).json({ error: "birthYear wajib diisi" });
    }

    const sql = `
      UPDATE directors
      SET name = $1, birthyear = $2
      WHERE id = $3
      RETURNING *
    `;

    try {
      const result = await db.query(sql, [name, birthYear, req.params.id]);

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Director tidak ditemukan" });
      }

      res.json(result.rows[0]);
    } catch (err) {
      next(err);
    }
  }
);

// DELETE DIRECTOR (ADMIN ONLY)
app.delete(
  "/directors/:id",
  [authenticateToken, authorizeRole("admin")],
  async (req, res, next) => {
    const sql = `
      DELETE FROM directors
      WHERE id = $1
      RETURNING *
    `;

    try {
      const result = await db.query(sql, [req.params.id]);

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Director tidak ditemukan" });
      }

     res.status(200).json({ message: 'Director berhasil dihapus' }); // Perbaiki syntax dan ganti status
  } catch (err) {
    next(err);
  }
  }
);

// === 404 HANDLER ===
app.use((req, res) => {
  res.status(404).json({ error: "Rute tidak ditemukan" });
});

// === ERROR HANDLER ===
app.use((err, req, res, next) => {
  console.error("[SERVER ERROR]", err.stack);
  res.status(500).json({ error: "Terjadi kesalahan pada server" });
});

// === START SERVER ===
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server aktif di http://localhost:${PORT}`);
});

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Film API. Try accessing /status or /movies.' });
});