/ PaypalWebhook.js

app.post("/api/paypal/verify", async (req, res) => {
  const userId = req.session.userId;

  if (!userId) return res.status(401).end();

  const { orderID } = req.body;

  // 🔐 verify with PayPal API
  const verified = await verifyPayPalPayment(orderID);

  if (!verified) {
    return res.status(400).json({ error: "Payment not verified" });
  }

  // ✅ mark user as paid
  await db.users.update({
    where: { id: userId },
    data: {
      paid: true,
      paidAt: new Date(),
      paymentMethod: "PayPal"
    }
  });

  req.session.paymentPending = false;

  res.json({ success: true });
});

// PayPal webhook endpoint
app.post("/api/paypal-webhook", async (req,res)=>{
  const event = req.body;

  if(event.event_type === "PAYMENT.CAPTURE.REFUNDED"){
      const orderID = event.resource.supplementary_data.related_ids.order_id;
      const member = await Members.findOne({ where:{ paypalOrderID: orderID }});
      if(member){
          member.paid = false;
          await member.save();

          // Notify member
          await transporter.sendMail({
              from: '"Kelowna Flower Gardens" <noreply@kelownaflowergardens.com>',
              to: member.email,
              subject: "Membership Refunded",
              text: "Your membership has been refunded. Access removed."
          });
      }
  }

  res.sendStatus(200);
});

 
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
    
  const express = require("express");
const db = require("../db");

const router = express.Router();

/* PAYPAL WEBHOOK */
router.post("/paypal/webhook", express.raw({ type: "*/*" }), (req, res) => {
  const event = JSON.parse(req.body.toString());

  if (event.event_type === "PAYMENT.CAPTURE.COMPLETED") {
    const email = event.resource.payer.email_address;

    db.prepare(`
      UPDATE users
      SET membership_status = 'active'
      WHERE email = ?
    `).run(email);
  }

  res.sendStatus(200);
});

module.exports = router;

npm install axios body-parser crypto


const crypto = require("crypto");
const axios = require("axios");

app.post("/api/paypal/webhook", express.raw({type: "application/json"}), async (req, res) => {
  const transmissionId = req.headers["paypal-transmission-id"];
  const timestamp = req.headers["paypal-transmission-time"];
  const certUrl = req.headers["paypal-cert-url"];
  const authAlgo = req.headers["paypal-auth-algo"];
  const transmissionSig = req.headers["paypal-transmission-sig"];
  const webhookId = process.env.PAYPAL_WEBHOOK_ID;

  const verificationBody = {
    auth_algo: authAlgo,
    cert_url: certUrl,
    transmission_id: transmissionId,
    transmission_sig: transmissionSig,
    transmission_time: timestamp,
    webhook_id: webhookId,
    webhook_event: req.body
  };

  // Verify webhook with PayPal
  const token = await getPayPalAccessToken();

  const verifyRes = await axios.post(
    "https://api-m.paypal.com/v1/notifications/verify-webhook-signature",
    verificationBody,
    {
      headers:{
        Authorization:`Bearer ${token}`,
        "Content-Type":"application/json"
      }
    }
  );

  if(verifyRes.data.verification_status !== "SUCCESS"){
    return res.sendStatus(400);
  }

  // ✅ PAYMENT CONFIRMED
  if(req.body.event_type === "PAYMENT.SALE.COMPLETED"){
    const txnId = req.body.resource.id;
    const email = req.body.resource.payer.payer_info.email;

    await db.query(
      `UPDATE users 
       SET paid=true, active=true, paypal_txn_id=$1 
       WHERE email=$2`,
      [txnId, email]
    );
  }

  res.sendStatus(200);
});


async function getPayPalAccessToken(){
    const res = await axios.post(
      "https://api-m.paypal.com/v1/oauth2/token",
      "grant_type=client_credentials",
      {
        auth:{
          username: process.env.PAYPAL_CLIENT_ID,
          password: process.env.PAYPAL_SECRET
        },
        headers:{
          "Content-Type":"application/x-www-form-urlencoded"
        }
      }
    );
    return res.data.access_token;
  }

  const { sendWelcomeEmail } = require("./mailer");

app.post("/api/paypal/webhook", async (req, res) => {
  const event = req.body;

  if (event.event_type === "PAYMENT.CAPTURE.COMPLETED") {

    const email = event.resource.payer.email_address;
    const txnId = event.resource.id;

    const user = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    if (user.rows.length) {
      await db.query(
        "UPDATE users SET paid=true, active=true, paypal_txn_id=$1 WHERE email=$2",
        [txnId, email]
      );

      await sendWelcomeEmail(user.rows[0], txnId);
    }
  }

  res.sendStatus(200);
});

  
