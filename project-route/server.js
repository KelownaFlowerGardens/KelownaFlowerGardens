// server.js

app.post("/api/admin/delete-member", requireAdmin, (req, res) => {
  const { id } = req.body;

  db.prepare("DELETE FROM users WHERE id = ?").run(id);

  res.json({ success: true });
});

app.post("/api/admin/toggle-member", requireAdmin, (req, res) => {
  const { id } = req.body;

  db.prepare(`
    UPDATE users
    SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END
    WHERE id = ?
  `).run(id);

  res.json({ success: true });
});

app.get("/api/admin/members", requireAdmin, (req, res) => {
  const members = db.prepare(`
    SELECT id, name, email, username, active, paid, created_at
    FROM users
    ORDER BY created_at DESC
  `).all();

  res.json(members);
});


const requireAdmin = require("./middleware/requireAdmin");

GET /api/admin/hosts
POST /api/admin/hosts/:id/status

app.post("/api/host-signup", upload.single("image"), (req, res) => {
    const { name, location, preferredDate, venueSize, description } = req.body;
  
    db.prepare(`
      INSERT INTO hosts
      (name, location, preferred_date, venue_size, description, image_path)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      name,
      location,
      preferredDate,
      venueSize,
      description,
      req.file ? req.file.path : null
    );
  
    res.json({ success: true });
  });
  

app.post("/api/member/accept-waiver", requireLogin, (req, res) => {
  db.run(
    "UPDATE members SET waiverAccepted = 1 WHERE id = ?",
    [req.session.userId],
    err => {
      if (err) {
        return res.status(500).json({ error: "Failed to save waiver" });
      }
      res.json({ success: true });
    }
  );
});

if (!user.waiverAccepted) {
    return res.redirect("/Success.html");
  }
  

app.get("/MembersDashboard.html",
    requireAuth,
    requireWaiverAccepted,
    (req, res) => {
      res.sendFile(__dirname + "/public/MembersDashboard.html");
    }
  );
  

app.use((req, res, next) => {
  console.log(req.method, req.url, req.session.userId || "guest");
  next();
});


app.use(cors({
  origin: "https://kelownaflowergardens.onrender.com",
  credentials: true
}));


app.post("/api/paypal/capture", async (req, res) => {
  const order = await capturePayPalOrder(req.body.orderID);

  if (order.status === "COMPLETED") {
    await db.query(
      "UPDATE members SET payment_status='paid' WHERE id=?",
      [req.session.userId]
    );

    req.session.paymentStatus = "paid";
    res.json({ success: true });
  } else {
    res.status(400).json({ error: "Payment failed" });
  }
});


paypal.Buttons({
  createOrder: () => fetch("/api/paypal/create").then(r => r.json()),
  onApprove: data => fetch("/api/paypal/capture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  })
}).render("#paypal-button");


app.get("/Payment.html", requireAuth);
app.get("/MembersDashboard.html", requireAuth, requirePayment);


import SQLiteStore from "connect-sqlite3";

app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.db",
      dir: "./db"
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);


import express from "express";
import session from "express-session";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,        // HTTPS on Render
      sameSite: "lax"
    }
  })
);

// 🔥 REQUIRED
app.use(express.static(path.join(process.cwd(), "public")));


app.get("/Payment.html", (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect("/Success.html");
  }
  next();
});

app.post("/api/register", async (req, res) => {
  const { username, email, password, plan } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  const result = await db.query(
    "INSERT INTO members (username, email, password, plan, payment_status) VALUES (?, ?, ?, ?, 'pending')",
    [username, email, hashed, plan]
  );

  req.session.userId = result.insertId;
  req.session.paymentStatus = "pending";

  res.json({ success: true });
});

req.session.userId = user._id;
req.session.paymentStatus = "pending";


app.get("/api/payment-status", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ allowed: false });
  }

  res.json({
    allowed: true,
    paid: req.session.paymentStatus === "paid"
  });
});

const resetLink = `https://kelownaflowergardens.com/reset-password.html?token=${token}`;

sendEmail(user.email, `
Click the link below to reset your password:
${resetLink}

This link expires in 1 hour.
`);

sendEmail(user.email, `
  Your password for Kelowna Flower Gardens was successfully changed.
  If this wasn’t you, please contact support immediately.
  `);

  // Node.js example using PayPal REST SDK
  app.post('/api/paypal-verify', async (req, res) => {
    const { orderID, userID } = req.body;
    const capture = await paypalClient.orders.capture(orderID);
    if(capture.status === 'COMPLETED'){
        await db.members.update({ paid:true }, { where: { id:userID } });
        // Send email/SMS
        sendEmail(userID, "Membership payment confirmed");
        sendSMS(userID, "Membership payment confirmed");
        res.send({ success:true });
    } else {
        res.status(400).send({ error:"Payment not completed" });
    }
});
// On refund
db.members.update({ paid:false }, { where:{ id:userID }});
sendEmail(userID, "Membership refunded — access removed");

function submitSignup(){
  const pass = password.value;
  const confirm = document.getElementById("confirm").value;

  if(pass !== confirm){
    document.getElementById("error").textContent =
      "Passwords do not match";
    return;
  }
  
POST /api/register-temp
Body: { username, email, plan, password }
DB: pending = true, paid = false
    username: username.value,
    email: email.value,
    plan: plan.value
  UPDATE members SET paid = true, pending = false WHERE id = ?
  }));


app.use(express.json());
app.use(cookieParser());

// ROUTES
import authRoutes from "./routes/auth.js";
import paymentRoutes from "./routes/payments.js";

app.use("/api/auth", authRoutes);
app.use("/api/payments", paymentRoutes);

// HEALTH CHECK (Render requires this)
app.get("/", (req, res) => {
  res.send("Backend running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on", PORT));


if (!strongRegex.test(password)) {
  return res.status(400).json({ error: "Weak password" });
}

const confirmValue = document.getElementById("confirmPassword").value;


app.get("/api/payment/session", (req, res) => {
  if (!req.session.userId || !req.session.paymentPending) {
    return res.status(401).end();
  }
  res.json({ ok: true });
});

app.get("/api/members", async (req,res)=>{
  const [rows] = await db.query(`
    SELECT username, full_name, location, bio, avatar
    FROM users
    WHERE profile_complete=1 AND show_public=1
  `);
  res.json(rows);
});


let avatarPath = null;
if(req.body.avatarBase64){
  avatarPath = saveBase64Image(req.body.avatarBase64, req.user.id);
}

const fs = require("fs");

function saveBase64Image(base64, userId){
  const data = base64.replace(/^data:image\/\w+;base64,/, "");
  const path = `uploads/avatars/${userId}.jpg`;
  fs.writeFileSync(path, Buffer.from(data, "base64"));
  return `/${path}`;
}

if(preference === "email") sendEmail(email, "Membership confirmed");
else if(preference === "text") sendSMS(phone, "Membership confirmed");


POST /api/register-temp
Body: { username, email, plan, password }
DB: pending = true, paid = false


// On refund
db.members.update({ paid:false }, { where:{ id:userID }});
sendEmail(userID, "Membership refunded — access removed");


// Node.js example using PayPal REST SDK
app.post('/api/paypal-verify', async (req, res) => {
  const { orderID, userID } = req.body;
  const capture = await paypalClient.orders.capture(orderID);
  if(capture.status === 'COMPLETED'){
      await db.members.update({ paid:true }, { where: { id:userID } });
      // Send email/SMS
      sendEmail(userID, "Membership payment confirmed");
      sendSMS(userID, "Membership payment confirmed");
      res.send({ success:true });
  } else {
      res.status(400).send({ error:"Payment not completed" });
  }
});


app.post("/api/reset-password", async (req, res) => {
  const { token, password } = req.body;

  const users = await db.query(
    "SELECT * FROM members WHERE reset_token=? AND reset_expires > ?",
    [token, Date.now()]
  );

  if (!users.length) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  const user = users[0];
  const hash = await bcrypt.hash(password, 12);

  await db.query(
    `UPDATE members
     SET password=?, reset_token=NULL, reset_expires=NULL
     WHERE id=?`,
    [hash, user.id]
  );

  // 🔐 AUTO LOGIN (SESSION)
  req.session.user = {
    id: user.id,
    username: user.username,
    avatar: user.avatar
  };

  res.json({ success: true });
});

const crypto = require("crypto");
const bcrypt = require("bcrypt");

// Request reset
app.post("/api/request-password-reset", async (req, res) => {
  const { email } = req.body;

  const user = await db.query(
    "SELECT id FROM members WHERE email = ?",
    [email]
  );

  if (!user.length) {
    // Always respond OK (prevent email enumeration)
    return res.sendStatus(200);
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 1000 * 60 * 30; // 30 mins

  await db.query(
    "UPDATE members SET reset_token=?, reset_expires=? WHERE email=?",
    [token, expires, email]
  );

  // SEND EMAIL HERE (example link)
  console.log(`Reset link:
  http://localhost:3000/reset-password.html?token=${token}`);

  res.sendStatus(200);
});


const express = require("express");
const nodemailer = require("nodemailer");
const multer = require("multer");
const upload = multer(); // for parsing multipart/form-data
const app = express();

// Parse JSON if needed
app.use(express.json());

app.post("/api/host-signup", upload.none(), async (req, res) => {
  const { name, email, phone, message } = req.body;

  try {
    // Configure the transporter (Gmail example, replace with your email SMTP)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "kelownaflowergardensl@gmail.com",
        pass: "xpjp gylb kkmu eyet"
      }
    });

    // Email options
    const mailOptions = {
      from: `"Member Application" <your.email@gmail.com>`,
      to: "kelownaflowergardensl@gmail.com",  // where you want to receive submissions
      subject: "New Host Application Submitted",
      html: `
        <h2>New Host Application</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone}</p>
        <p><strong>Message:</strong> ${message}</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ success: true, message: "Application sent to email!" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to send email." });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));

if (!text || !currentRoom) return;


div.onclick = () => {
  currentRoom = [username, m.username].sort().join("#");
  chatWith.textContent = m.username;
  messagesDiv.innerHTML = "";
};

const socket = io({
  withCredentials: true
});


app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.sendStatus(401);
  res.json({
    username: req.session.user.username,
    email: req.session.user.email
  });
});

let username = null;

fetch("/api/me", { credentials: "include" })
  .then(res => res.json())
  .then(user => {
    username = user.username;
  })
  .catch(() => {
    alert("Session expired. Please log in again.");
    location.href = "Login.html";
  });


const onlineUsers = new Map();

io.on("connection", socket => {
  const session = socket.request.session;

  // 🚫 Block unauthenticated users
  if (!session || !session.user) {
    return socket.disconnect(true);
  }

  const username = session.user.username; // from login system
  socket.username = username;

  onlineUsers.set(socket.id, username);

  // Join private room for direct messages
  socket.join(username);

  // Broadcast updated member list
  io.emit("members", getMembers());

  socket.on("chatMessage", msg => {
    io.to(msg.room).emit("chatMessage", {
      ...msg,
      username
    });
  });

  socket.on("typing", room => {
    socket.to(room).emit("typing", room, username);
  });

  socket.on("stopTyping", room => {
    socket.to(room).emit("stopTyping", room);
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    io.emit("members", getMembers());
  });
});

function getMembers() {
  const unique = [...new Set(onlineUsers.values())];
  return unique.map(u => ({ username: u, online: true }));
}

const wrap = middleware => (socket, next) =>
  middleware(socket.request, {}, next);

io.use(wrap(sessionMiddleware));

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const onlineUsers = new Map();

/* =========================
   SOCKET LOGIC
========================= */
io.on("connection", socket => {
  const username = socket.handshake.auth?.username || `User${socket.id.slice(0,4)}`;

  onlineUsers.set(socket.id, { username });
  socket.join(username);

  io.emit("members", getMembers());

  socket.on("chatMessage", msg => {
    io.to(msg.room).emit("chatMessage", msg);
  });

  socket.on("typing", (room, user) => {
    socket.to(room).emit("typing", room, user);
  });

  socket.on("stopTyping", room => {
    socket.to(room).emit("stopTyping", room);
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(socket.id);
    io.emit("members", getMembers());
  });
});

/* =========================
   HELPERS
========================= */
function getMembers() {
  const names = {};
  for (const { username } of onlineUsers.values()) {
    names[username] = true;
  }
  return Object.keys(names).map(u => ({
    username: u,
    online: true
  }));
}

server.listen(3000, () =>
  console.log("✅ Socket.IO server running on port 3000")
);

if (data.rsvpCount >= 35) {
  rsvpButton.disabled = true;
  rsvpButton.textContent = "Event Full";
}

app.post("/api/rsvp", async (req, res) => {
  const userId = req.user.id; // from auth middleware
  const { eventId } = req.body;

  // Count current RSVPs
  const count = await db.query(
    "SELECT COUNT(*) FROM rsvps WHERE event_id = ?",
    [eventId]
  );

  if (count[0]["COUNT(*)"] >= MAX_CAPACITY) {
    return res.status(409).send("Event full");
  }

  // Prevent duplicate RSVP
  const existing = await db.query(
    "SELECT id FROM rsvps WHERE event_id = ? AND user_id = ?",
    [eventId, userId]
  );

  if (existing.length) {
    return res.status(200).send("Already RSVP'd");
  }

  // Insert RSVP
  await db.query(
    "INSERT INTO rsvps (event_id, user_id) VALUES (?, ?)",
    [eventId, userId]
  );

  // Optional: notify admin
  await notifyAdmin({
    eventId,
    userId,
    type: "RSVP"
  });

  res.sendStatus(200);
});

const MAX_CAPACITY = 35;

{
  "user_id": 42,
  "event_id": "official-launch",
  "event_id": "first-garden-party",
  "response": "yes"
}

app.post("/api/rsvp", requireLogin, (req, res) => {
  const { eventId } = req.body;
  const userId = req.session.userId;

  db.get(
    "SELECT waiverAccepted FROM members WHERE id = ?",
    [userId],
    (err, row) => {
      if (!row || !row.waiverAccepted) {
        return res.status(403).json({ error: "Waiver required" });
      }

      db.run(
        `INSERT OR IGNORE INTO rsvps (member_id, event_id)
         VALUES (?, ?)`,
        [userId, eventId],
        () => res.json({ success: true })
      );
    }
  );
});

if (!user.waiverAccepted) return 403;

fetch("/api/rsvp", { credentials: "include" })

app.get("/api/events/:id/calendar.ics", requireLogin, (req, res) => {

  db.get(`SELECT * FROM events WHERE id=?`, [req.params.id], (err, e) => {

    const ics = `
BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
SUMMARY:${e.title}
DTSTART:${e.date.replace(/[-:]/g,"")}
DESCRIPTION:${e.description}
END:VEVENT
END:VCALENDAR
    `;

    res.header("Content-Type", "text/calendar");
    res.send(ics);
  });
});

const cron = require("node-cron");

cron.schedule("0 10 * * *", () => {
  db.all(`
    SELECT m.phone, e.title, e.date
    FROM rsvps r
    JOIN members m ON m.id = r.member_id
    JOIN events e ON e.id = r.event_id
    WHERE date(e.date) = date('now','+1 day')
  `, (err, rows) => {
    rows.forEach(r =>
      sendSMS(r.phone, `🌸 Reminder: ${r.title} is tomorrow!`)
    );
  });
});

const twilio = require("twilio")(SID, TOKEN);

function sendSMS(to, msg) {
  return twilio.messages.create({
    from: "+1XXXXXXXXXX",
    to,
    body: msg
  });
}

app.post("/api/sms/stop", (req,res)=>{
  db.run(
    "UPDATE members SET sms_opt_in = 0 WHERE phone = ?",
    [req.body.From]
  );
});


SELECT m.phone
FROM rsvps r
JOIN members m ON m.id = r.member_id
WHERE m.sms_opt_in = 1
  AND m.phone IS NOT NULL;


app.post("/api/profile", requireLogin, (req, res) => {
  const { phone, sms_opt_in } = req.body;

  db.run(
    `UPDATE members
     SET phone = ?, sms_opt_in = ?
     WHERE id = ?`,
    [phone || null, sms_opt_in ? 1 : 0, req.session.userId],
    () => res.json({ success: true })
  );
});


async function saveProfile(){
  await fetch("/api/profile", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      phone: phone.value,
      sms_opt_in: smsOpt.checked
    })
  });

  alert("Profile updated");
}

const QRCode = require("qrcode");

app.get("/api/rsvp/:id/qrcode", requireLogin, async (req, res) => {
  const data = `RSVP:${req.params.id}`;
  const qr = await QRCode.toDataURL(data);
  res.json({ qr });
});

app.get("/api/admin/events/:id/rsvps.csv", requireAdmin, (req, res) => {

  db.all(
    `SELECT m.name, m.email, r.created_at
     FROM rsvps r
     JOIN members m ON m.id = r.member_id
     WHERE r.event_id = ?`,
    [req.params.id],
    (err, rows) => {

      let csv = "Name,Email,RSVP Date\n";
      rows.forEach(r => {
        csv += `"${r.name}","${r.email}","${r.created_at}"\n`;
      });

      res.header("Content-Type", "text/csv");
      res.attachment("rsvps.csv");
      res.send(csv);
    }
  );
});

if (res.status === 202) {
  alert("Event is full. You’re on the waitlist 🌸");
  btn.textContent = "Waitlisted";
  btn.disabled = true;
}


if (event.capacity > 0 && event.count >= event.capacity) {

  db.run(
    `INSERT OR IGNORE INTO waitlist (member_id, event_id)
     VALUES (?, ?)`,
    [req.session.userId, eventId]
  );

  return res.status(202).json({
    waitlisted: true,
    message: "Event is full. You’ve been added to the waitlist."
  });
}

const res = await fetch(url, {...});

if (res.status === 403) {
  btn.textContent = "🚫 Event Full";
  btn.disabled = true;
}

app.post("/api/rsvp", requireLogin, (req, res) => {
  const { eventId } = req.body;

  db.get(
    `SELECT capacity,
      (SELECT COUNT(*) FROM rsvps WHERE event_id = ?) AS count
     FROM events WHERE id = ?`,
    [eventId, eventId],
    (err, event) => {

      if (!event) return res.status(404).json({ error: "Event not found" });

      if (event.capacity > 0 && event.count >= event.capacity) {
        return res.status(403).json({ error: "Event is full" });
      }

      db.run(
        `INSERT OR IGNORE INTO rsvps (member_id, event_id)
         VALUES (?, ?)`,
        [req.session.userId, eventId],
        err => {
          if (err) return res.status(500).json({ error: "RSVP failed" });
          res.json({ success: true });
        }
      );
    }
  );
});

app.post("/api/rsvp", requireLogin, (req, res) => {
  const { eventId } = req.body;

  db.get(
    `SELECT name, email FROM members WHERE id = ?`,
    [req.session.userId],
    (err, member) => {

      db.run(
        `INSERT OR IGNORE INTO rsvps (member_id, event_id)
         VALUES (?, ?)`,
        [req.session.userId, eventId],
        err => {
          if (err) return res.status(500).json({ error: "RSVP failed" });

          transporter.sendMail({
            from: `"Kelowna Flower Gardens" <${process.env.ADMIN_EMAIL}>`,
            to: process.env.ADMIN_EMAIL,
            subject: "🌸 New RSVP Received",
            html: `
              <h3>New RSVP</h3>
              <p><strong>Name:</strong> ${member.name}</p>
              <p><strong>Email:</strong> ${member.email}</p>
              <p><strong>Event ID:</strong> ${eventId}</p>
            `
          });

          res.json({ success: true });
        }
      );
    }
  );
});

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_EMAIL_PASS
  }
});

app.get("/api/admin/rsvps/:eventId", requireAdmin, (req, res) => {
  db.all(
    `SELECT m.name, m.email, r.created_at
     FROM rsvps r
     JOIN members m ON m.id = r.member_id
     WHERE r.event_id = ?`,
    [req.params.eventId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed" });
      res.json(rows);
    }
  );
});

app.post("/api/rsvp/cancel", requireLogin, (req, res) => {
  const { eventId } = req.body;

  db.run(
    `DELETE FROM rsvps WHERE member_id = ? AND event_id = ?`,
    [req.session.userId, eventId],
    err => {
      if (err) return res.status(500).json({ error: "Cancel failed" });
      res.json({ success: true });
    }
  );
});

app.post("/api/rsvp", requireLogin, (req, res) => {
  const { eventId } = req.body;

  db.run(
    `INSERT OR IGNORE INTO rsvps (member_id, event_id)
     VALUES (?, ?)`,
    [req.session.userId, eventId],
    err => {
      if (err) return res.status(500).json({ error: "RSVP failed" });
      res.json({ success: true });
    }
  );
});

document.getElementById("continueBtn").onclick = async () => {
  const res = await fetch("/api/member/accept-waiver", {
    method: "POST",
    credentials: "include"
  });

  if (res.ok) {
    window.location.href = "MembersDashboard.html";
  }
};

app.post("/api/member/accept-waiver", requireLogin, (req, res) => {
  db.get(
    "SELECT name, email FROM members WHERE id = ?",
    [req.session.userId],
    (err, member) => {
      if (err || !member) {
        return res.status(500).json({ error: "Member not found" });
      }

      db.run(
        "UPDATE members SET waiverAccepted = 1 WHERE id = ?",
        [req.session.userId],
        async err => {
          if (err) {
            return res.status(500).json({ error: "Failed to save waiver" });
          }

          /* EMAIL ADMIN */
          try {
            await transporter.sendMail({
              from: `"Kelowna Flower Gardens" <${process.env.ADMIN_EMAIL}>`,
              to: process.env.ADMIN_EMAIL,
              subject: "New Waiver Accepted",
              html: `
                <h3>Waiver Accepted</h3>
                <p><strong>Name:</strong> ${member.name}</p>
                <p><strong>Email:</strong> ${member.email}</p>
                <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
              `
            });
          } catch (mailErr) {
            console.error("Email failed:", mailErr);
            // ⚠️ Do NOT block the user if email fails
          }

          res.json({ success: true });
        }
      );
    }
  );
});


const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",      // change if not Gmail
  port: 587,
  secure: false,
  auth: {
    user: process.env.ADMIN_EMAIL,
    pass: process.env.ADMIN_EMAIL_PASS
  }
});

document.getElementById("continueBtn").onclick = async () => {
  const res = await fetch("/api/member/accept-waiver", {
    method: "POST",
    credentials: "include"
  });

  if (res.ok) {
    window.location.href = "MembersDashboard.html";
  } else {
    alert("Unable to continue.");
  }
};

app.get(
  "/api/member/dashboard",
  requireLogin,
  requireWaiverAccepted,
  (req, res) => {
    res.json({ ok: true });
  }
);

function requireAdmin(req,res,next){
  if(!req.session.user || !req.session.user.isAdmin){
    return res.status(403).send("Forbidden");
  }
  next();
}

app.get("/MembersDashboard.html",
  requireAuth,
  requireWaiverAccepted,
  (req, res) => {
    res.sendFile(__dirname + "/public/MembersDashboard.html");
  }
);
function requireWaiverAccepted(req, res, next) {
  const user = db.prepare(
    "SELECT waiverAccepted FROM users WHERE id = ?"
  ).get(req.session.user.id);

  if (!user || user.waiverAccepted !== 1) {
    return res.redirect("/Success.html");
  }

  next();
}



  db.prepare(`
    UPDATE members
    SET waiverAccepted = 1,
        waiverAcceptedAt = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(req.session.userId);

  res.sendStatus(200);
});
app.post("/api/accept-waiver", requireAuth, (req, res) => {
  db.prepare(`
    UPDATE users
    SET waiverAccepted = 1,
        waiverAcceptedAt = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(req.session.user.id);

  res.json({ success: true });
});


  overlay.style.display = "none";
  document.body.style.overflow = "auto";

  document.querySelector(".card").style.pointerEvents = "auto";
  dashboardBtn.disabled = false;
});

app.post("/api/member-selection", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Login required" });
  }

  const { selections } = req.body;
  const { id, name, email } = req.session.user;

  const stmt = db.prepare(`
    INSERT INTO member_selections (member_id, member_name, selection)
    VALUES (?, ?, ?)
  `);

  selections.forEach(sel => stmt.run(id, name, sel));

  // 🔔 Notify admin
  transporter.sendMail({
    to: "admin@kelownaflowergardens.com",
    subject: "New Member Selection",
    text: `
Member: ${name}
Email: ${email}

Selections:
${selections.join("\n")}
    `
  });

  res.json({ success: true });
});
app.get("/api/my-selections", (req, res) => {
  if (!req.session.user) return res.sendStatus(401);

  const rows = db.prepare(`
    SELECT selection, created_at
    FROM member_selections
    WHERE member_id = ?
  `).all(req.session.user.id);

  res.json(rows);
});
const exists = db.prepare(`
  SELECT 1 FROM member_selections WHERE member_id = ?
`).get(id);

if (exists) {
  return res.status(400).json({ error: "Selection already submitted" });
}

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.your-email-provider.com",
  port: 587,
  secure: false,
  auth: {
    user: "kelownaflowergardens@gmail.com",
    pass: "xpjp gylb kkmu eyet"
  }
});
app.post("/api/member-selection", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const { selections } = req.body;
  const { id, name, email } = req.session.user;

  const stmt = db.prepare(`
    INSERT INTO member_selections (member_id, member_name, selection)
    VALUES (?, ?, ?)
  `);

  selections.forEach(sel => {
    stmt.run(id, name, sel);
  });

  // 📧 EMAIL ADMIN
  await transporter.sendMail({
    from: '"KFG Website" <admin@kelownaflowergardens.com>',
    to: "admin@kelownaflowergardens.com",
    subject: "New Member Selection",
    html: `
      <h3>New Member Selection</h3>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Selections:</strong></p>
      <ul>
        ${selections.map(s => `<li>${s}</li>`).join("")}
      </ul>
    `
  });

  res.json({ success: true });
});

const multer = require("multer");
const path = require("path");
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/hosts");
  },
  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueName + path.extname(file.originalname));
  }
});

const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only images allowed"));
    }
    cb(null, true);
  },
  storage
});

app.post(
  "/api/host-signup",
  upload.single("image"),
  async (req, res) => {
    try {
      const { name, location, preferredDate, venueSize, description } = req.body;

      const mailOptions = {
        from: `"Kelowna Flower Gardens" <${process.env.EMAIL_USER}>`,
        to: process.env.ADMIN_EMAIL,
        subject: "🌸 New Host Sign Up Submission",
        html: `
          <h2>New Host Application</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Location:</strong> ${location}</p>
          <p><strong>Preferred Date:</strong> ${preferredDate}</p>
          <p><strong>Venue Size:</strong> ${venueSize}</p>
          <p><strong>Description:</strong><br>${description}</p>
        `,
        attachments: req.file
          ? [
              {
                filename: req.file.originalname,
                path: req.file.path
              }
            ]
          : []
      };

      await transporter.sendMail(mailOptions);

      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Submission failed" });
    }
  }
);

const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const Database = require("better-sqlite3");
const cors = require("cors");

const app = express();
const db = new Database("members.db");

app.use(cors({
  origin: "https://www.kelownaflowergardens.com",
  credentials: true
}));
app.use(express.json());

app.use(session({
  secret: "super-secret-key",
  resave: false,
  saveUninitialized: false
}));

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const cors = require("cors");
const SQLite = require("better-sqlite3");

db.prepare(`
  CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    membership_status TEXT DEFAULT 'pending'
  )
`).run();

app.post("/api/register", async (req, res) => {
  const { name, email, username, password } = req.body;

  if (!name || !email || !username || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  const hash = await bcrypt.hash(password, 10);

  try {
    db.prepare(`
      INSERT INTO users (name, email, username, password_hash)
      VALUES (?, ?, ?, ?)
    `).run(name, email, username, hash);

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user) return res.status(401).json({ error: "Invalid login" });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: "Invalid login" });

  req.session.userId = user.id;
  res.json({ success: true });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.status(401).json(null);

  const user = db.prepare(
    "SELECT id, name, email, membership_status FROM users WHERE id = ?"
  ).get(req.session.userId);

  res.json(user);
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.listen(3000, () => {
  console.log("API running on port 3000");
});

fetch("https://api.yoursite.com/api/register", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    name,
    email,
    username,
    password
  })
});

fetch("/api/me", { credentials: "include" })
  .then(res => res.json())
  .then(user => {
    if (user) showAvatar(user.name);
  });
  membership_status = 'active'

  document.getElementById("signupForm").onsubmit = async e => {
    e.preventDefault();
  
    const data = Object.fromEntries(new FormData(e.target));
  
    const res = await fetch("/api/register", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
  
    if (res.ok) window.location.href = "Payment.html";
  };

  paypal.Buttons({
    createOrder: (data, actions) => {
      return actions.order.create({
        purchase_units: [{
          amount: { value: "56.00" },
          description: "Annual Membership"
        }],
        application_context: {
          shipping_preference: "NO_SHIPPING"
        }
      });
    }
  }).render("#paypal-button");
  app.post("/api/paypal/webhook", express.raw({ type: "*/*" }), (req, res) => {
    const event = JSON.parse(req.body);
  
    if (event.event_type === "PAYMENT.CAPTURE.COMPLETED") {
      const email = event.resource.payer.email_address;
  
      db.prepare(`
        UPDATE users 
        SET membership_status='active' 
        WHERE email=?
      `).run(email);
    }
  
    res.sendStatus(200);
  });
  POST /api/login
  fetch("/api/me", { credentials: "include" })
  .then(r => r.json())
  .then(user => {
    if (user) document.body.classList.add("logged-in");
  });
  app.get("/api/member-only", (req, res) => {
    if (!req.session.userId) return res.sendStatus(401);
    res.json({ ok: true });
  });
  POST https://www.google.com/recaptcha/api/siteverify
      

  require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cors = require("cors");

const authRoutes = require("./routes/auth.js");
const paypalRoutes = require("./paypal");

const app = express();

app.use(cors({
  origin: "http://localhost:5500", // your frontend
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
  }
}));

app.use("/api", authRoutes);
app.use("/api", paypalRoutes);

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(3000, () => {
  console.log("KFG backend running on http://localhost:3000");
});

// ------------------ SETUP ------------------
const app = express();
const PORT = 3000;

// Allow frontend access
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------ SESSION ------------------
app.use(session({
  secret: "kfg-secret-session-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,        // true only with HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// ------------------ DATABASE ------------------
const db = new SQLite("members.db");

// Create table if it doesn't exist
db.prepare(`
  CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    paid INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ------------------ ROUTES ------------------

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { name, email, username, password } = req.body;

  if (!name || !email || !username || !password) {
    return res.status(400).json({ error: "All fields required" });
  }

  const hashed = await bcrypt.hash(password, 10);

  try {
    db.prepare(`
      INSERT INTO members (name, email, username, password)
      VALUES (?, ?, ?, ?)
    `).run(name, email, username, hashed);

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
});
membership_status = 'active'
paypal.Buttons({
    createOrder: (data, actions) => {
      return actions.order.create({
        purchase_units: [{
          amount: { value: "56.00" },
          description: "Annual Membership"
        }],
        application_context: {
          shipping_preference: "NO_SHIPPING"
        }
      });
    }

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(`
    SELECT * FROM members WHERE username = ?
  `).get(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    paid: user.paid
  };

  res.json({ success: true });
});

// CHECK SESSION
app.get("/api/session", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ------------------ START SERVER ------------------
app.listen(PORT, () => {
  console.log(`🌸 KFG Backend running on http://localhost:${PORT}`);
});

if(!user.active){
  return res.status(403).json({error:"Membership inactive"});
}

function requireAdmin(req, res, next){
  if(!req.session.user || !req.session.user.is_admin){
    return res.status(403).json({ error: "Admin access only" });
  }
  next();
}

app.get("/api/admin/members", requireAdmin, async (req, res) => {
  const result = await db.query(`
    SELECT 
      name,
      email,
      paid,
      active,
      paypal_txn_id,
      created_at
    FROM users
    ORDER BY created_at DESC
  `);
  res.json(result.rows);
});

app.get("/api/admin/members.csv", requireAdmin, async (req, res) => {
  const result = await db.query(`
    SELECT 
      name,
      email,
      paid,
      active,
      paypal_txn_id,
      created_at
    FROM users
    ORDER BY created_at DESC
  `);

  let csv = "Name,Email,Paid,Active,PayPal Transaction,Joined\n";
  result.rows.forEach(u => {
    csv += `"${u.name}","${u.email}",${u.paid},${u.active},"${u.paypal_txn_id || ""}","${u.created_at}"\n`;
  });

  res.header("Content-Type", "text/csv");
  res.attachment("kelowna-flower-gardens-members.csv");
  res.send(csv);
});



app.use(session({
  name: "kfg_session",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  }
}));


const rateLimit = require("express-rate-limit");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
});

app.use("/api/login", authLimiter);
app.use("/api/signup", authLimiter);


const helmet = require("helmet");
app.use(helmet());


function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

app.get("/api/admin/members", requireAdmin, (req, res) => {
  // admin data
});

app.use((req, res, next) => {
  console.log(req.method, req.url);
  next();
});


app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM members WHERE username = ?",
    [username],
    async (err, user) => {
      if (!user) {
        return res.json({ success: false, error: "Invalid login" });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.json({ success: false, error: "Invalid login" });
      }

      // Create session
      req.session.user = {
        id: user.id,
        name: user.name,
        username: user.username,
        paid: user.paid
      };

      res.json({ success: true });
    }
  );
});
import crypto from "crypto";

app.post("/api/password-reset-request", async (req, res) => {
  const { email } = req.body;

  const user = db.prepare(
    "SELECT * FROM members WHERE email = ?"
  ).get(email);

  if (!user) {
    return res.json({ success: true }); // prevent email enumeration
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 3600000; // 1 hour

  db.prepare(`
    UPDATE members
    SET reset_token = ?, reset_expires = ?
    WHERE email = ?
  `).run(token, expires, email);

  const resetLink = `https://kelownaflowergardens.com/reset-password.html?token=${token}`;

  await sendResetEmail(email, resetLink);

  res.json({ success: true });
});

import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "kelownaflowergardens@gmail.com",
    pass: "xpjp gylb kkmu eyet"
  }
});

async function sendResetEmail(email, link) {
  await transporter.sendMail({
    from: "Kelowna Flower Gardens",
    to: email,
    subject: "Password Reset",
    html: `
      <p>Click the link below to reset your password:</p>
      <a href="${link}">${link}</a>
      <p>This link expires in 1 hour.</p>
    `
  });
}

app.post("/api/password-reset", async (req, res) => {
  const { token, newPassword } = req.body;

  const user = db.prepare(`
    SELECT * FROM members
    WHERE reset_token = ?
    AND reset_expires > ?
  `).get(token, Date.now());

  if (!user) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  const hashed = await bcrypt.hash(newPassword, 10);

  db.prepare(`
    UPDATE members
    SET password = ?, reset_token = NULL, reset_expires = NULL
    WHERE id = ?
  `).run(hashed, user.id);

  res.json({ success: true });
});



app.get("/api/session", (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

<script>

fetch("http://localhost:3000/api/session", {
  credentials: "include"
})
.then(res => res.json())
.then(data => {
  const navAuth = document.getElementById("nav-auth");

  if (!data.loggedIn) {
    // Logged OUT
    navAuth.innerHTML = `
      <a href="Login.html" class="btn-outline">Login</a>
      <a href="Members.html" class="btn-primary">Become a Member</a>
    `;
    return;
  }

  // Logged IN
  navAuth.innerHTML = `
    <button class="avatar-btn" id="avatarBtn">
      <img src="KFGL.jpg" alt="Member Avatar">
    </button>

    <div class="avatar-menu" id="avatarMenu">
      <a href="MembersDashboard.html">Dashboard</a>
      <a href="Profile.html">My Profile</a>
      <a href="#" id="logoutBtn">Log Out</a>
    </div>
  `;

  // Toggle menu
  document.getElementById("avatarBtn").onclick = () => {
    document.getElementById("avatarMenu").classList.toggle("show");
  };

  // Logout
  document.getElementById("logoutBtn").onclick = async () => {
    await fetch("http://localhost:3000/api/logout", {
      method: "POST",
      credentials: "include"
    });
    window.location.href = "LoggedOut.html";
  };
});
</script>
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});
import crypto from "crypto";

app.post("/api/password-reset-request", async (req, res) => {
  const { email } = req.body;

  const user = db.prepare(
    "SELECT * FROM members WHERE email = ?"
  ).get(email);

  if (!user) {
    return res.json({ success: true }); // prevent email enumeration
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 3600000; // 1 hour

  db.prepare(`
    UPDATE members
    SET reset_token = ?, reset_expires = ?
    WHERE email = ?
  `).run(token, expires, email);

  const resetLink = `https://yourdomain.com/reset-password.html?token=${token}`;

  await sendResetEmail(email, resetLink);

  res.json({ success: true });
});


const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cors = require("cors");
const Database = require("better-sqlite3");

const app = express();
const db = new Database("db.sqlite");

// ----- Create users table if missing -----
db.prepare(`
  CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    plan TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ----- Middleware -----
app.use(express.json());

app.use(cors({
  origin: "http://localhost:5500", // or your frontend URL
  credentials: true
}));

app.use(session({
  secret: "kfg-super-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true only if HTTPS
}));

// ----- REGISTER ROUTE -----
app.post("/api/register", async (req, res) => {
  const { username, email, password, plan } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // Check existing user
  const exists = db.prepare(
    "SELECT id FROM users WHERE username = ? OR email = ?"
  ).get(username, email);

  if (exists) {
    return res.status(409).json({ error: "User already exists" });
  }

  // Hash password
  const hash = await bcrypt.hash(password, 12);

  // Insert user
  const result = db.prepare(`
    INSERT INTO users (username, email, password, plan)
    VALUES (?, ?, ?, ?)
  `).run(username, email, hash, plan);

  // Create session
  req.session.user = {
    id: result.lastInsertRowid,
    username,
    status: "pending"
  };

  res.json({ success: true });
});

// ----- START SERVER -----
app.listen(3000, () => {
  console.log("✅ KFG Backend running on http://localhost:3000");
});

app.post("/api/paypal/webhook1", express.json(), (req, res) => {
  const event = req.body;
  
  // Only care about completed payments
  if (event.event_type === "PAYMENT.CAPTURE.COMPLETED") {

    const capture = event.resource;
    const orderId = capture.supplementary_data.related_ids.order_id;
    const email = capture.payer.email_address;

    // Activate user
    const user = db.prepare(
      "SELECT * FROM users WHERE email = ? AND status = 'pending'"
    ).get(email);

    if (!user) {
      return res.sendStatus(200); // Ignore unknown payments
    }

    db.prepare(`
      UPDATE users
      SET status = 'active',
          paypal_order_id = ?,
          paid_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(orderId, user.id);

    console.log(`✅ Membership activated for ${email}`);
  }

  res.sendStatus(200);
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Save minimal info in session
  req.session.user = {
    id: user.id,
    username: user.username
  };

  res.json({
    success: true,
    status: user.status // pending or active
  });
});


app.get("/api/session", (req, res) => {
  if (!req.session.user) {
    return res.json({ loggedIn: false });
  }

  const user = db.prepare(
    "SELECT status FROM users WHERE id = ?"
  ).get(req.session.user.id);

  res.json({
    loggedIn: true,
    status: user.status,
    username: req.session.user.username
  });
});


app.get("/api/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const user = db.prepare(`
    SELECT username, email, plan, status, created_at
    FROM users
    WHERE id = ?
  `).get(req.session.user.id);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (user.status !== "active") {
    return res.status(403).json({ error: "Payment required" });
  }

  res.json(user);
});


<script>
const messages = []; // temporary in-memory storage
const chatInput = document.getElementById("chatInput");
const sendBtn = document.getElementById("sendBtn");
const messagesDiv = document.getElementById("messages");

// Display messages
function renderMessages() {
  messagesDiv.innerHTML = "";
  messages.forEach(msg => {
    const div = document.createElement("div");
    div.textContent = msg.text;
    div.className = "message " + (msg.self ? "self" : "other");
    messagesDiv.appendChild(div);
  });
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Send message
sendBtn.addEventListener("click", () => {
  const text = chatInput.value.trim();
  if (!text) return;
  messages.push({ text, self: true });
  chatInput.value = "";
  renderMessages();

  // Simulate other members response (placeholder)
  setTimeout(() => {
    messages.push({ text: "Member response: " + text, self: false });
    renderMessages();
  }, 1000);
});

// Optional: send message on Enter key
chatInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") sendBtn.click();
});
</script>

// server.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static("public")); // serve HTML/CSS/JS files

// Session setup (for member authentication)
app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: true,
}));

// Dummy login check middleware
function requireMember(req, res, next) {
  if (req.session.user && req.session.user.paid) {
    next();
  } else {
    res.status(401).send("Unauthorized");
  }
}

// Example login route (replace with real auth)
app.get("/login/:username", (req, res) => {
  req.session.user = { username: req.params.username, paid: true };
  res.send("Logged in as " + req.param
    const express = require("express");
    const http = require("http");
    const { Server } = require("socket.io");
    const session = require("express-session");
    const sqlite3 = require("sqlite3").verbose();
    const path = require("path");
    
    const app = express();
    const server = http.createServer(app);
    const io = new Server(server);
    
    // Setup SQLite database
    const db = new sqlite3.Database("./chat.db");
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      avatar TEXT,
      room TEXT,
      text TEXT,
      timestamp TEXT
    )`);
    
    // Session middleware
    app.use(session({
      secret: "supersecretkey",
      resave: false,
      saveUninitialized: true
    }));
    
    // Serve static files
    app.use(express.static("public"));
    app.use(express.json());
    
    // Dummy login route
    app.get("/login/:username", (req, res) => {
      req.session.user = { username: req.params.username, paid: true, avatar: "/avatars/default.png" };
      res.send("Logged in as " + req.params.username);
    });
    
    // Middleware to protect members
    function requireMember(req, res, next) {
      if (req.session.user && req.session.user.paid) return next();
      res.status(401).send("Unauthorized");
    }
    
    // Serve dashboard
    app.get("/dashboard", requireMember, (req, res) => {
      res.sendFile(path.join(__dirname, "public/dashboard.html"));
    });
    
    // API: get last 50 messages
    app.get("/api/messages/:room", requireMember, (req, res) => {
      const room = req.params.room;
      db.all("SELECT * FROM messages WHERE room=? ORDER BY id DESC LIMIT 50", [room], (err, rows) => {
        if (err) return res.status(500).send(err);
        res.json(rows.reverse());
      });
    });
    
    // Socket.io real-time
    io.use((socket, next) => {
      const username = socket.handshake.auth.username;
      const avatar = socket.handshake.auth.avatar;
      if (!username) return next(new Error("Unauthorized"));
      socket.username = username;
      socket.avatar = avatar;
      next();
    });
    
    io.on("connection", (socket) => {
      const room = socket.handshake.auth.room || "general";
      socket.join(room);
    
      // Broadcast join
      socket.to(room).emit("message", {
        username: "System",
        avatar: "",
        text: `${socket.username} joined the room.`,
        timestamp: new Date().toLocaleTimeString()
      });
    
      // Load last 50 messages
      db.all("SELECT * FROM messages WHERE room=? ORDER BY id DESC LIMIT 50", [room], (err, rows) => {
        if (!err) {
          rows.reverse().forEach(msg => socket.emit("message", msg));
        }
      });
    
      // Listen for chat
      socket.on("chatMessage", (msgText) => {
        const msg = {
          username: socket.username,
          avatar: socket.avatar,
          text: msgText,
          room: room,
          timestamp: new Date().toLocaleTimeString()
        };
        db.run("INSERT INTO messages(username, avatar, room, text, timestamp) VALUES(?,?,?,?,?)",
          [msg.username, msg.avatar, msg.room, msg.text, msg.timestamp]
        );
        io.to(room).emit("message", msg);
      });
    
      socket.on("disconnect", () => {
        socket.to(room).emit("message", {
          username: "System",
          avatar: "",
          text: `${socket.username} left the room.`,
          timestamp: new Date().toLocaleTimeString()
        });
      });
    });
    
    server.listen(3000, () => console.log("Server running on http://localhost:3000"));
// server.js
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// SQLite DB for messages
const db = new sqlite3.Database("./chat.db");
db.run(`CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  avatar TEXT,
  room TEXT,
  text TEXT,
  timestamp TEXT
)`);

// Session middleware
const sessionMiddleware = session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: true
});
app.use(sessionMiddleware);

// Share session with Socket.io
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

// Serve static files
app.use(express.static("public"));
app.use(express.json());

// Dummy login route (replace with your real authentication)
app.post("/api/login", (req, res) => {
  const { username } = req.body;
  // Example: fetch member from your DB
  const member = {
    username,
    paid: true,
    avatar: "/avatars/default.png" // replace with member avatar from DB
  };
  req.session.user = member;
  res.json({ success: true, user: member });
});

// Middleware to protect members
function requireMember(req, res, next) {
  if
    
  app.get("/api/session", (req, res) => {
    if (req.session.user && req.session.user.paid) {
      res.json(req.session.user);
    } else {
      res.status(401).json({ loggedIn: false });
    }
  });
// Store online members in memory
const onlineMembers = new Map(); // socket.id => { username, avatar }

io.on("connection", (socket) => {
  const sessionUser = socket.request.session.user;
  if (!sessionUser || !sessionUser.paid) return socket.disconnect(true);

  const username = sessionUser.username;
  const avatar = sessionUser.avatar;

  // Track online members
  onlineMembers.set(socket.id, { username, avatar });
  io.emit("updateMembers", Array.from(onlineMembers.values())); // broadcast member list

  // Join default "general" room
  const room = "general";
  socket.join(room);

  // Broadcast join
  socket.to(room).emit("message", {
    username: "System",
    avatar: "",
    text: `${username} joined the general chat.`,
    timestamp: new Date().toLocaleTimeString()
  });

  // Private chat: socket joins a room with another member
  socket.on("startPrivateChat", (targetUsername) => {
    const privateRoom = [username, targetUsername].sort().join("#");
    socket.join(privateRoom);
    socket.emit("privateRoomJoined", privateRoom);
  });

  // Listen for messages
  socket.on("chatMessage", ({ text, room }) => {
    const msg = {
      username,
      avatar,
      text,
      room,
      timestamp: new Date().toLocaleTimeString()
    };

    db.run(
      "INSERT INTO messages(username, avatar, room, text, timestamp) VALUES(?,?,?,?,?)",
      [msg.username, msg.avatar, msg.room, msg.text, msg.timestamp]
    );

    io.to(room).emit("message", msg);
  });

  socket.on("disconnect", () => {
    onlineMembers.delete(socket.id);
    io.emit("updateMembers", Array.from(onlineMembers.values())); // update list
    socket.to(room).emit("message", {
      username: "System",
      avatar: "",
      text: `${username} left the chat.`,
      timestamp: new Date().toLocaleTimeString()
    });
  });
});
const io = require("socket.io")(server);
const onlineMembers = {};

io.use((socket, next) => {
  const { username, avatar } = socket.handshake.auth;
  if(!username) return next(new Error("Unauthorized"));
  socket.username = username;
  socket.avatar = avatar;
  next();
});

io.on("connection", socket => {
  onlineMembers[socket.username] = { avatar: socket.avatar, socketId: socket.id };
  io.emit("updateMembers", Object.keys(onlineMembers).map(u => ({ username:u, avatar:onlineMembers[u].avatar })));

  socket.on("chatMessage", ({ text, room }) => {
    const timestamp = new Date().toLocaleTimeString();
    io.to(room).emit("message", { username: socket.username, avatar: socket.avatar, text, timestamp });
  });

  socket.on("startPrivateChat", targetUsername => {
    const room = [socket.username, targetUsername].sort().join("#");
    socket.join(room);
    if(onlineMembers[targetUsername]) io.sockets.sockets.get(onlineMembers[targetUsername].socketId).join(room);
  });

  socket.on("disconnect", () => {
    delete onlineMembers[socket.username];
    io.emit("updateMembers", Object.keys(onlineMembers).map(u => ({ username:u, avatar:onlineMembers[u].avatar })));
  });
});
const express = require("express");
const multer = require("multer");
const path = require("path");
const { ensureAuthenticated, updateUserAvatar } = require("./routes/auth.js"); // your auth

const router = express.Router();

const storage = multer.diskStorage({
  destination: "./public/uploads/avatars/",
  filename: (req, file, cb) => {
    cb(null, req.user.id + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

router.post("/api/upload-avatar", ensureAuthenticated, upload.single("avatar"), async (req, res) => {
  try {
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    await updateUserAvatar(req.user.id, avatarUrl); // save to DB
    res.json({ avatarUrl });
  } catch (err) {
    res.status(500).json({ error: "Failed to upload avatar" });
  }
});

module.exports = router;
io.on("connection", (socket) => {
  // Store avatar in socket session
  socket.on("auth", ({ username, avatar }) => {
    socket.username = username;
    socket.avatar = avatar;
  });

  // Handle avatar update
  socket.on("updateAvatar", ({ avatarUrl }) => {
    socket.avatar = avatarUrl;
    // Broadcast updated member list to all clients
    const members = Array.from(io.sockets.sockets.values()).map(s => ({
      username: s.username,
      avatar: s.avatar
    }));
    io.emit("updateMembers", members);
  });

  // existing chat events...
});
socket.on("updateMembers", members => {
  membersContainer.innerHTML = "";
  members.forEach(member => {
    if (member.username === username) return;
    const div = document.createElement("div");
    div.className = "memberItem";
    div.innerHTML = `<img src="${member.avatar || '/default-avatar.png'}" class="msgAvatar"> ${member.username}`;
    div.onclick = () => {
      currentRoom = [username, member.username].sort().join("#");
      socket.emit("startPrivateChat", member.username);
      messagesDiv.innerHTML = "";
    };
    membersContainer.appendChild(div);
  });
});
const onlineUsers = new Map(); // userId → { username, avatar }
io.on("connection", (socket) => {

  socket.on("auth", ({ userId, username, avatar }) => {
    socket.userId = userId;
    socket.username = username;
    socket.avatar = avatar;

    onlineUsers.set(userId, { username, avatar });
    io.emit("updateMembers", Array.from(onlineUsers.values()));
  });
  socket.on("updateAvatar", async ({ avatarUrl }) => {
    socket.avatar = avatarUrl;
  
    // Update memory
    onlineUsers.set(socket.userId, {
      username: socket.username,
      avatar: avatarUrl
    });
  
    // Broadcast avatar update
    io.emit("avatarUpdated", {
      userId: socket.userId,
      avatar: avatarUrl
    });
  
    io.emit("updateMembers", Array.from(onlineUsers.values()));
  });
  socket.on("chatMessage", ({ text, room }) => {
    const msg = {
      userId: socket.userId,
      username: socket.username,
      text,
      timestamp: new Date().toLocaleTimeString()
    };
  
    io.to(room).emit("message", msg);
  });
  const avatarCache = {};
  socket.on("updateMembers", members => {
    members.forEach(m => {
      avatarCache[m.userId] = m.avatar;
    });
  });
  function renderMessage(msg) {
    const div = document.createElement("div");
    div.className = "message";
    div.dataset.userId = msg.userId;
  
    const avatar = avatarCache[msg.userId] || "/default-avatar.png";
  
    div.innerHTML = `
      <img src="${avatar}" class="msgAvatar">
      <span><strong>${msg.username}</strong> ${msg.text}</span>
    `;
  
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }
  socket.on("avatarUpdated", ({ userId, avatar }) => {
    avatarCache[userId] = avatar;
  
    document.querySelectorAll(`.message[data-user-id="${userId}"] img`)
      .forEach(img => img.src = avatar);
  });
  avatarForm.addEventListener("submit", async e => {
    e.preventDefault();
  
    const formData = new FormData();
    formData.append("avatar", avatarInput.files[0]);
  
    const res = await fetch("/api/upload-avatar", {
      method: "POST",
      credentials: "include",
      body: formData
    });
  
    const data = await res.json();
  
    avatarPreview.src = data.avatarUrl;
  
    socket.emit("updateAvatar", { avatarUrl: data.avatarUrl });
  });
  const onlineUsers = new Map();

  io.on("connection", socket => {
    socket.on("auth", ({ userId, username, avatar }) => {
      socket.userId = userId;
      socket.username = username;
      socket.avatar = avatar;
  
      onlineUsers.set(userId, { userId, username, avatar, online: true });
      io.emit("updateMembers", Array.from(onlineUsers.values()));
    });
  
    socket.on("disconnect", () => {
      if (socket.userId) {
        onlineUsers.delete(socket.userId);
        io.emit("updateMembers", Array.from(onlineUsers.values()));
      }
    });
  });
  socket.on("updateMembers", members => {
    membersContainer.innerHTML = "";
  
    members.forEach(m => {
      const div = document.createElement("div");
      div.className = "memberItem";
      div.innerHTML = `
        <span class="status ${m.online ? 'online' : 'offline'}"></span>
        <img src="${m.avatar}" class="msgAvatar">
        ${m.username}
      `;
      membersContainer.appendChild(div);
    });
  });
  let unreadCount = 0;

  socket.on("message", msg => {
    if (!messengerOpen) {
      unreadCount++;
      document.getElementById("chatBadge").textContent = unreadCount;
      new Audio("/notify.mp3").play();
    }
  });
  sendBtn.onclick = () => {
    if (imageInput.files[0]) {
      const form = new FormData();
      form.append("image", imageInput.files[0]);
  
      fetch("/api/upload-chat-image", {
        method:"POST",
        body: form
      }).then(r => r.json()).then(data => {
        socket.emit("chatMessage", { image: data.url, room });
      });
    } else {
      socket.emit("chatMessage", { text: chatInput.value, room });
    }
  };
  socket.on("chatMessage", msg => {
    io.to(msg.room).emit("message", {
      userId: socket.userId,
      username: socket.username,
      text: msg.text || null,
      image: msg.image || null,
      timestamp: Date.now()
    });
  });

  function renderMessage(msg){
    const div = document.createElement("div");
    div.innerHTML = `
      <img src="${avatarCache[msg.userId]}" class="msgAvatar">
      ${msg.text ? `<p>${msg.text}</p>` : ""}
      ${msg.image ? `<img src="${msg.image}" class="chatImage">` : ""}
    `;
    messages.appendChild(div);
  }
  socket.on("chatMessage", async msg => {
    await db.query(
      "INSERT INTO messages (room, sender_id, text, image) VALUES ($1,$2,$3,$4)",
      [msg.room, socket.userId, msg.text, msg.image]
    );
  });
  socket.on("joinRoom", async room => {
    socket.join(room);
    const history = await db.query(
      "SELECT * FROM messages WHERE room=$1 ORDER BY created_at ASC",
      [room]
    );
    socket.emit("chatHistory", history.rows);
  });
  socket.on("chatHistory", msgs => {
    messages.innerHTML = "";
    msgs.forEach(renderMessage);
  });

  
  chatToggle.onclick = () => {
    messengerModal.classList.toggle("open");
    unreadCount = 0;
    chatBadge.textContent = "";
  };
  socket.on("messageDelivered", async ({ messageId }) => {
    await db.query(
      "UPDATE messages SET delivered=true WHERE id=$1",
      [messageId]
    );
  });
  socket.on("messagesRead", async ({ room, readerId }) => {
    await db.query(
      "UPDATE messages SET read=true WHERE room=$1 AND sender_id != $2",
      [room, readerId]
    );
  
    io.to(room).emit("readReceipt", { readerId });
  });
  function renderMessage(msg){
    const status = msg.read ? "✔✔" : msg.delivered ? "✔" : "";
    message.innerHTML += `<span class="receipt">${status}</span>`;
  }
  socket.on("typing", room => {
    socket.to(room).emit("typing", socket.username);
  });
  
  socket.on("stopTyping", room => {
    socket.to(room).emit("stopTyping");
  });
  chatInput.addEventListener("input", () => {
    socket.emit("typing", currentRoom);
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      socket.emit("stopTyping", currentRoom);
    }, 800);
  });
  
  socket.on("typing", name => {
    typingIndicator.textContent = `${name} is typing...`;
  });
  
  socket.on("stopTyping", () => {
    typingIndicator.textContent = "";
  });

  socket.on("adminDeleteMessage", async ({ messageId }) => {
    if (socket.role !== "admin") return;
  
    await db.query("DELETE FROM messages WHERE id=$1", [messageId]);
    io.emit("messageDeleted", messageId);
  });

  const mutedUsers = new Set();

socket.on("adminMuteUser", userId => {
  if (socket.role !== "admin") return;
  mutedUsers.add(userId);
});

self.addEventListener("push", event => {
  const data = event.data.json();
  self.registration.showNotification(data.title, {
    body: data.body,
    icon: "/icon-192.png"
  });
});
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js");
}
await webpush.sendNotification(subscription, JSON.stringify({
  title: "New Message",
  body: `${sender}: ${text}`
}));
messengerModal.addEventListener("touchstart", e => startY = e.touches[0].clientY);
messengerModal.addEventListener("touchend", e => {
  if (e.changedTouches[0].clientY - startY > 120) {
    messengerModal.classList.remove("open");
  }
});


const { v4: uuid } = require("uuid");

io.on("connection", socket => {

  socket.on("chatMessage", msg => {
    const message = {
      id: uuid(),
      room: msg.room,
      sender: socket.username,
      text: msg.text,
      timestamp: Date.now(),
      readBy: [socket.username]
    };

    io.to(msg.room).emit("message", message);
  });

  socket.on("messageRead", ({ messageId, room, username }) => {
    io.to(room).emit("messageRead", {
      messageId,
      username
    });
  });

});





function renderMessage(msg){
  const div = document.createElement("div");
  div.className = "message " + (msg.sender === username ? "self" : "other");
  div.dataset.id = msg.id;

  div.innerHTML = `
    <span class="text">${msg.text}</span>
    ${msg.sender === username ? `<span class="receipt" id="r-${msg.id}">✔</span>` : ""}
  `;

  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}
socket.on("message", msg => {
  renderMessage(msg);

  if(msg.sender !== username){
    socket.emit("messageRead", {
      messageId: msg.id,
      room: currentRoom,
      username
    });
  }
});
socket.on("messageRead", ({ messageId, username: reader }) => {
  const receipt = document.getElementById(`r-${messageId}`);
  if(receipt){
    receipt.textContent = "✔✔";
    receipt.title = `Read by ${reader}`;
  }
});

io.on("connection", socket => {

  socket.on("typing:start", room => {
    socket.to(room).emit("typing:start", socket.username);
  });

  socket.on("typing:stop", room => {
    socket.to(room).emit("typing:stop", socket.username);
  });

});
let typingTimeout;

chatInput.addEventListener("input", () => {
  socket.emit("typing:start", currentRoom);

  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    socket.emit("typing:stop", currentRoom);
  }, 800);
});
const typingIndicator = document.getElementById("typingIndicator");

socket.on("typing:start", user => {
  typingIndicator.textContent = `${user} is typing...`;
});

socket.on("typing:stop", () => {
  typingIndicator.textContent = "";
});
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: "public/uploads",
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  }
});

const upload = multer({ storage });

app.post("/api/upload", upload.single("image"), (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}` });
});
const imageInput = document.getElementById("imageInput");
const imageBtn = document.getElementById("imageBtn");

imageBtn.onclick = () => imageInput.click();

imageInput.onchange = async () => {
  const file = imageInput.files[0];
  if(!file) return;

  const formData = new FormData();
  formData.append("image", file);

  const res = await fetch("/api/upload", {
    method: "POST",
    body: formData,
    credentials: "include"
  });

  const data = await res.json();

  socket.emit("chatMessage", {
    room: currentRoom,
    image: data.url
  });
};

socket.on("chatMessage", msg => {
  const message = {
    id: uuid(),
    room: msg.room,
    sender: socket.username,
    avatar: socket.avatar,
    text: msg.text || null,
    image: msg.image || null,
    timestamp: Date.now(),
    readBy: [socket.username]
  };

  io.to(msg.room).emit("message", message);
});


function renderMessage(msg){
  const div = document.createElement("div");
  div.className = "message " + (msg.sender === username ? "self" : "other");
  div.dataset.id = msg.id;

  let content = "";

  if(msg.text){
    content += `<div class="msgText">${msg.text}</div>`;
  }

  if(msg.image){
    content += `
      <img src="${msg.image}" class="msgImage"
           onclick="window.open('${msg.image}', '_blank')">
    `;
  }

  div.innerHTML = `
    ${msg.avatar ? `<img src="${msg.avatar}" class="msgAvatar">` : ""}
    ${content}
    ${msg.sender === username ? `<span class="receipt" id="r-${msg.id}">✔</span>` : ""}
  `;

  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
const emojiBtn = document.getElementById("emojiBtn");

emojiBtn.onclick = () => {
  chatInput.value += "😊";
  chatInput.focus();
};

socket.on("chatMessage", async msg => {
  const message = {
    id: uuid(),
    room: msg.room,
    sender: socket.username,
    avatar: socket.avatar,
    text: msg.text || null,
    image: msg.image || null,
    timestamp: Date.now(),
    readBy: [socket.username]
  };

  await db.query(
    `INSERT INTO messages
     (id, room, sender, avatar, text, image, timestamp, read_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      message.id,
      message.room,
      message.sender,
      message.avatar,
      message.text,
      message.image,
      message.timestamp,
      JSON.stringify(message.readBy)
    ]
  );

  io.to(message.room).emit("message", message);
});

socket.on("loadHistory", async room => {
  const result = await db.query(
    `SELECT * FROM messages
     WHERE room = $1
     ORDER BY timestamp ASC
     LIMIT 50`,
    [room]
  );

  socket.emit("chatHistory", result.rows);
});

function openRoom(room){
  currentRoom = room;
  messagesDiv.innerHTML = "";
  socket.emit("loadHistory", room);
}

div.onclick = () => {
  const room = [username, member.username].sort().join("#");
  openRoom(room);
};
socket.on("chatHistory", messages => {
  messages.forEach(renderMessage);
});
socket.on("messageRead", async ({ messageId, room, username }) => {

  await db.query(
    `UPDATE messages
     SET read_by = read_by || $1
     WHERE id = $2 AND NOT read_by @> $1`,
    [JSON.stringify([username]), messageId]
  );

  io.to(room).emit("messageRead", { messageId, username });
});

socket.on("chatHistory", messages => {
  messages.forEach(msg => {
    renderMessage(msg);
    if(msg.sender !== username){
      socket.emit("messageRead", {
        messageId: msg.id,
        room: currentRoom,
        username
      });
    }
  });
});

let unreadCount = 0;

socket.on("message", msg => {
  renderMessage(msg);

  // If modal is closed, increment badge
  if(messengerModal.style.display !== "flex" && msg.sender !== username){
    unreadCount++;
    const badge = document.getElementById("chatBadge");
    badge.textContent = unreadCount;
    badge.style.display = unreadCount > 0 ? "inline-block" : "none";
  }
});
toggleBtn.onclick = () => {
  messengerModal.style.display = "flex";
  unreadCount = 0;
  document.getElementById("chatBadge").style.display = "none";

  // Mark all messages as read in DB
  socket.emit("markRoomRead", currentRoom);
};


socket.on("markRoomRead", async room => {
  await db.query(
    `UPDATE messages
     SET read_by = array_append(read_by, $1)
     WHERE room = $2 AND NOT read_by @> ARRAY[$1]::varchar[]`,
    [socket.username, room]
  );
});


if ("Notification" in window) {
  Notification.requestPermission();
}

socket.on("message", msg => {
  if(messengerModal.style.display !== "flex" && msg.sender !== username){
    if(Notification.permission === "granted"){
      new Notification(`New message from ${msg.sender}`, {
        body: msg.text || "Image",
        icon: msg.avatar || "/default-avatar.png"
      });
    }
  }
});

toggleBtn.onclick = () => messengerModal.classList.toggle("open");

// Request permission for notifications
if ("Notification" in window) {
  if (Notification.permission === "default") {
    Notification.requestPermission().then(permission => {
      console.log("Notification permission:", permission);
    });
  }
}
socket.on("message", msg => {
  renderMessage(msg);

  // Only notify if message is from another user and chat modal is closed
  if (messengerModal.style.display !== "flex" && msg.username !== username) {
    unreadCount++;
    badge.style.display = "inline";
    badge.textContent = unreadCount;

    // Push notification
    if (Notification.permission === "granted") {
      new Notification(`New message from ${msg.username}`, {
        body: msg.type === "image" ? "📷 Image message" : msg.text,
        icon: msg.avatar || "/default-avatar.png",
        tag: msg.room
      });
    }
  }
});

if (Notification.permission === "granted") {
  new Notification(`New message from ${msg.username}`, {
    body: msg.type === "image" ? "📷 Image message" : msg.text,
    icon: msg.avatar || "/default-avatar.png",
    tag: msg.room
  }).onclick = () => {
    window.focus();
    messengerModal.style.display = "flex";
    unreadCount = 0;
    badge.style.display = "none";
  };
}

io.on("connection", socket => {
  const { username } = socket.auth;

  // Typing indicator
  socket.on("typing", (room) => {
    socket.to(room).emit("userTyping", username);
  });

  socket.on("stopTyping", (room) => {
    socket.to(room).emit("userStopTyping", username);
  });

  // Mark room as read
  socket.on("markRoomRead", (room) => {
    socket.to(room).emit("userRead", username);
  });

  // Chat message
  socket.on("chatMessage", (msg) => {
    io.to(msg.room).emit("message", { ...msg, timestamp: new Date().toLocaleTimeString() });
  });

  // Joining rooms
  socket.on("startPrivateChat", (targetUser) => {
    const room = [username, targetUser].sort().join("#");
    socket.join(room);
  });
});
// Request permission for notifications
if ("Notification" in window) {
  if (Notification.permission === "default") {
    Notification.requestPermission().then(permission => {
      console.log("Notification permission:", permission);
    });
  }
}
socket.on("message", msg => {
  renderMessage(msg);

  // Only notify if message is from another user and chat modal is closed
  if (messengerModal.style.display !== "flex" && msg.username !== username) {
    unreadCount++;
    badge.style.display = "inline";
    badge.textContent = unreadCount;

    // Push notification
    if (Notification.permission === "granted") {
      new Notification(`New message from ${msg.username}`, {
        body: msg.type === "image" ? "📷 Image message" : msg.text,
        icon: msg.avatar || "/default-avatar.png",
        tag: msg.room
      });
    }
  }
});
if (Notification.permission === "granted") {
  new Notification(`New message from ${msg.username}`, {
    body: msg.type === "image" ? "📷 Image message" : msg.text,
    icon: msg.avatar || "/default-avatar.png",
    tag: msg.room
  }).onclick = () => {
    window.focus();
    messengerModal.style.display = "flex";
    unreadCount = 0;
    badge.style.display = "none";
  };
}
document.addEventListener("DOMContentLoaded", () => {
  const messengerModal = document.getElementById("messengerModal");
  const toggleBtn = document.getElementById("messengerToggle");
  const closeBtn = document.getElementById("closeMessenger");

  toggleBtn.onclick = () => messengerModal.style.display = "flex";
  closeBtn.onclick = () => messengerModal.style.display = "none";
});
const messengerModal = document.getElementById("messengerModal");
const toggleBtn = document.getElementById("messengerToggle");
const closeBtn = document.getElementById("closeMessenger");
const MessageSchema = new mongoose.Schema({
  room: String,
  senderId: String,
  senderName: String,
  avatar: String,
  type: { type:String, enum:["text","image"], default:"text" },
  content: String,
  readBy: [String],
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Message", MessageSchema);
io.use((socket,next)=>{
  if(!socket.request.session.user) return next(new Error("unauthorized"));
  socket.user = socket.request.session.user;
  next();
});

io.on("connection", socket => {
  socket.join("global");

  socket.on("joinRoom", room => socket.join(room));

  socket.on("chatMessage", async msg => {
    const message = await Message.create({
      room: msg.room,
      senderId: socket.user.id,
      senderName: socket.user.username,
      avatar: socket.user.avatar,
      content: msg.text,
      type: msg.type,
      readBy: [socket.user.id]
    });
    io.to(msg.room).emit("chatMessage", message);
  });

  socket.on("markRead", async ({room,userId})=>{
    await Message.updateMany(
      { room, readBy:{ $ne:userId }},
      { $push:{ readBy:userId }}
    );
  });

  socket.on("typing", room => {
    socket.to(room).emit("typing", socket.user.username);
  });

  socket.on("stopTyping", room => {
    socket.to(room).emit("stopTyping");
  });

  socket.on("disconnect", ()=>{/* update online status */});
});
socket.on("adminDeleteMessage", async id=>{
  if(!socket.user.isAdmin) return;
  await Message.findByIdAndDelete(id);
  io.emit("deleteMessage", id);
});
if(msg.senderId === currentUserId){
  const allRead = msg.readBy.length > 1;
  receipt.textContent = allRead ? "✔✔" : "✔";
}
self.addEventListener("push", e=>{
  const data = e.data.json();
  self.registration.showNotification(data.title,{
    body:data.body,
    icon:"/icon.png"
  });
});
webpush.sendNotification(user.subscription,{
  title:"New Message",
  body:`${sender}: ${text}`
});
if(navigator.vibrate) navigator.vibrate(10);
// server.js
const express = require("express");
const http = require("http");
const session = require("express-session");
const SQLite = require("better-sqlite3");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ---------- DATABASE ----------
const db = new SQLite("chat.db");

db.prepare(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT,
    username TEXT,
    text TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.static("public"));

const sessionMiddleware = session({
  secret: "kfg-secret",
  resave: false,
  saveUninitialized: false
});

app.use(sessionMiddleware);

// Share session with Socket.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

// ---------- AUTH (TEMP – hooks into your real login later) ----------
app.post("/api/login", (req, res) => {
  const { username } = req.body;
  req.session.user = { username, paid: true };
  res.json({ success: true });
});

app.get("/api/session", (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

// ---------- SOCKET CHAT ----------
io.on("connection", socket => {
  const user = socket.request.session.user;
  if (!user || !user.paid) return socket.disconnect();

  const room = "general";
  socket.join(room);

  // Send history
  const history = db.prepare(
    "SELECT * FROM messages WHERE room=? ORDER BY id DESC LIMIT 50"
  ).all(room).reverse();

  socket.emit("history", history);

  socket.on("chatMessage", text => {
    db.prepare(
      "INSERT INTO messages (room, username, text) VALUES (?, ?, ?)"
    ).run(room, user.username, text);

    io.to(room).emit("message", {
      username: user.username,
      text,
      time: new Date().toLocaleTimeString()
    });
  });
});

// ---------- START ----------
server.listen(3000, () => {
  console.log("🌸 Chat server running on http://localhost:3000");
});

app.use("/uploads", express.static("uploads"));
app.post("/api/member-selection", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }

  const { selections } = req.body;
  const { id, name } = req.session.user;

  const stmt = db.prepare(`
    INSERT INTO member_selections (member_id, member_name, selection)
    VALUES (?, ?, ?)
  `);

  selections.forEach(sel => {
    stmt.run(id, name, sel);
  });

  res.json({ success: true });
});

/*
fetch("http://localhost:3000/api/session", {
  credentials: "include"
})
.then(res => res.json())
.then(data => {
  if (!data.loggedIn) {
    window.location.href = "Login.html";
  }
});
*/


          
