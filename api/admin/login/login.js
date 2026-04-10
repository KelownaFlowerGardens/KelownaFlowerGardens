const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const db = require("better-sqlite3")("chat.db");

// Admin login
router.post("/", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    // Find admin in database
    const admin = db.prepare(
      "SELECT * FROM admins WHERE username = ?"
    ).get(username);

    if (!admin) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare password
    const validPassword = await bcrypt.compare(password, admin.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Save admin session
    req.session.user = {
      id: admin.id,
      username: admin.username,
      role: "admin"
    };

    res.json({
      success: true,
      user: req.session.user
    });

  } catch (err) {
    console.error("Admin login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
