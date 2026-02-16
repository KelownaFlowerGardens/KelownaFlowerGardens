// requireAdmin.js

app.get("/api/admin/events/:id/rsvps.csv", requireAdmin, (req, res) => {
  const { id } = req.params;

  const rows = db.prepare(`
    SELECT
      u.name,
      u.email,
      r.created_at,
      r.checked_in
    FROM rsvps r
    JOIN users u ON u.id = r.user_id
    WHERE r.event_id = ?
  `).all(id);

  let csv = "Name,Email,RSVP Date,Checked In\n";

  rows.forEach(row => {
    csv += `"${row.name}","${row.email}","${row.created_at}","${row.checked_in ? "Yes" : "No"}"\n`;
  });

  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=rsvps.csv");
  res.send(csv);
});


app.get("/api/admin/payments", requireAdmin, (req, res) => {
  const payments = db.prepare(`
    SELECT p.*, u.email
    FROM payments p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.created_at DESC
  `).all();

  res.json(payments);
});


app.post("/api/admin/hosts/:id/status", requireAdmin, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  db.prepare(`
    UPDATE hosts
    SET status = ?
    WHERE id = ?
  `).run(status, id);

  res.json({ success: true });
});


app.get("/api/admin/hosts", requireAdmin, (req, res) => {
  const hosts = db.prepare(`
    SELECT *
    FROM hosts
    ORDER BY created_at DESC
  `).all();

  res.json(hosts);
});


function requireAdmin(req, res, next) {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }
  
    const user = db
      .prepare("SELECT is_admin FROM users WHERE id = ?")
      .get(req.session.userId);
  
    if (!user || user.is_admin !== 1) {
      return res.status(403).json({ error: "Admin access required" });
    }
  
    next();
  }
  
  module.exports = requireAdmin;
  
  app.get("/api/admin/members", requireAdmin, ...)

function requireAdmin(req, res, next) {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.sendStatus(403);
  }
  next();
}

app.get("/Payment.html", requireAuth);
app.get("/MembersDashboard.html", requireAuth, requirePayment);


function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/Members.html");
  }
  next();
}

function requirePayment(req, res, next) {
  if (req.session.paymentStatus !== "paid") {
    return res.redirect("/Payment.html");
  }
  next();
}
