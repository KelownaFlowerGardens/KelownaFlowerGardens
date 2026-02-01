// Middleware.js

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


app.get("/MembersDashboard.html", requireAuth, requireCompleteProfile);


function requireCompleteProfile(req,res,next){
  if(!req.user.profile_complete){
    return res.redirect("/complete-profile.html?reminder=1");
  }
  next();
}

if(!user.profile_complete){
  return res.redirect("/complete-profile.html");
}

export function isAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  }
  function requireActiveMember(req, res, next) {
    if (!req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }
  
    const user = db.prepare(
      "SELECT status FROM users WHERE id = ?"
    ).get(req.session.user.id);
  
    if (user.status !== "active") {
      return res.status(403).json({ error: "Payment required" });
    }
  
    next();
  }
  function adminOnly(req, res, next) {
    if (!req.session.user || !req.session.user.isAdmin) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  }
  
  