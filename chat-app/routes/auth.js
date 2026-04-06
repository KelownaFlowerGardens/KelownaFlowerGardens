// auth.js

function requireWaiverAccepted(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not logged in" });
  }

  db.get(
    "SELECT waiverAccepted FROM members WHERE id = ?",
    [req.session.userId],
    (err, row) => {
      if (err || !row) {
        return res.status(500).json({ error: "User lookup failed" });
      }

      if (row.waiverAccepted !== 1) {
        return res.status(403).json({
          error: "Waiver not accepted"
        });
      }

      next();
    }
  );
}


const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../db");

const router = express.Router();

/* REGISTER */
router.post("/register", async (req, res) => {
  const { name, email, username, password } = req.body;

  const hash = await bcrypt.hash(password, 12);

  try {
    db.prepare(`
      INSERT INTO users (name, email, username, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(name, email, username, hash);

    res.sendStatus(201);
  } catch {
    res.status(400).json({ error: "User already exists" });
  }
});

/* LOGIN */
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(`
    SELECT * FROM users WHERE username = ?
  `).get(username);

  if (!user) return res.sendStatus(401);

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.sendStatus(401);

  req.session.userId = user.id;
  res.json({ ok: true });
});

/* LOGOUT */
router.post("/logout", (req, res) => {
  req.session.destroy(() => res.sendStatus(200));
});

/* CURRENT USER */
router.get("/me", (req, res) => {
  if (!req.session.userId) return res.json(null);

  const user = db.prepare(`
    SELECT id, name, username, membership_status
    FROM users WHERE id = ?
  `).get(req.session.userId);

  res.json(user);
});

module.exports = router;
