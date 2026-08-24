const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const Razorpay = require("razorpay");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.warn("WARNING: Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env");
}

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

const dataDir = path.join(__dirname, "data");
const ordersFile = path.join(dataDir, "orders.json");
fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(ordersFile)) fs.writeFileSync(ordersFile, "[]");

function readOrders() {
  try { return JSON.parse(fs.readFileSync(ordersFile, "utf8")); }
  catch { return []; }
}

function writeOrders(orders) {
  fs.writeFileSync(ordersFile, JSON.stringify(orders, null, 2));
}

/*
  IMPORTANT:
  - Never expose RAZORPAY_KEY_SECRET to the browser.
  - Amount is recalculated on the server from the submitted cart.
  - In production, replace the demo product catalog below with your DB.
*/
const products = {
  "1": { id: "1", name: "Calathea Plant", price: 599 },
  "2": { id: "2", name: "Monstera Plant", price: 799 },
  "3": { id: "3", name: "Fiddle Leaf", price: 699 },
  "4": { id: "4", name: "Snake Plant", price: 399 },
  "5": { id: "5", name: "Cactus", price: 299 },
  "6": { id: "6", name: "Areca Palm", price: 699 }
};

app.use(express.json({ limit: "200kb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/config", (req, res) => {
  res.json({
    keyId: process.env.RAZORPAY_KEY_ID || "",
    storeName: process.env.STORE_NAME || "Plantia"
  });
});

app.post("/api/create-order", async (req, res) => {
  try {
    const { items, customer } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Cart is empty." });
    }

    if (!customer?.name || !customer?.email || !customer?.phone ||
        !customer?.address || !customer?.city || !customer?.state ||
        !customer?.pincode) {
      return res.status(400).json({ error: "Complete delivery details are required." });
    }

    let totalRupees = 0;
    const safeItems = [];

    for (const item of items) {
      const product = products[String(item.id)];
      const quantity = Math.max(1, Math.min(20, Number(item.quantity || 1)));

      if (!product) {
        return res.status(400).json({ error: "Invalid product in cart." });
      }

      totalRupees += product.price * quantity;
      safeItems.push({
        id: product.id,
        name: product.name,
        price: product.price,
        quantity
      });
    }

    const amount = Math.round(totalRupees * 100);
    if (amount <= 0 || amount > 50000000) {
      return res.status(400).json({ error: "Invalid order amount." });
    }

    const receipt = `plantia_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`;

    const order = await razorpay.orders.create({
      amount,
      currency: "INR",
      receipt,
      notes: {
        customer_email: customer.email,
        customer_phone: customer.phone
      },
      payment_capture: 1
    });

    const dbOrders = readOrders();
    dbOrders.push({
      localId: crypto.randomUUID(),
      razorpayOrderId: order.id,
      amount,
      currency: "INR",
      status: "created",
      customer,
      items: safeItems,
      createdAt: new Date().toISOString()
    });
    writeOrders(dbOrders);

    res.json({
      orderId: order.id,
      amount,
      currency: "INR",
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error("create-order:", error);
    res.status(500).json({ error: "Unable to create Razorpay order." });
  }
});

app.post("/api/verify-payment", (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: "Missing payment verification fields." });
    }

    const orders = readOrders();
    const savedOrder = orders.find(o => o.razorpayOrderId === razorpay_order_id);

    if (!savedOrder) {
      return res.status(404).json({ error: "Order not found." });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(`${savedOrder.razorpayOrderId}|${razorpay_payment_id}`)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(razorpay_signature);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ error: "Payment signature verification failed." });
    }

    savedOrder.status = "payment_verified";
    savedOrder.paymentId = razorpay_payment_id;
    savedOrder.signature = razorpay_signature;
    savedOrder.paidAt = new Date().toISOString();

    writeOrders(orders);

    res.json({
      success: true,
      orderId: savedOrder.razorpayOrderId,
      paymentId: savedOrder.paymentId,
      message: "Payment verified successfully."
    });
  } catch (error) {
    console.error("verify-payment:", error);
    res.status(500).json({ error: "Payment verification failed." });
  }
});

/*
  Razorpay webhook endpoint.
  Configure this URL in Razorpay Dashboard:
  https://YOUR-DOMAIN.com/api/razorpay-webhook

  For production, process the event asynchronously after fast signature validation.
*/
app.post(
  "/api/razorpay-webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["x-razorpay-signature"];
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!signature || !secret) return res.status(400).send("Webhook not configured");

    const expected = crypto
      .createHmac("sha256", secret)
      .update(req.body)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(signature);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).send("Invalid webhook signature");
    }

    let event;
    try {
      event = JSON.parse(req.body.toString("utf8"));
    } catch {
      return res.status(400).send("Invalid JSON");
    }

    const orders = readOrders();
    const razorpayOrderId = event?.payload?.payment?.entity?.order_id;

    if (razorpayOrderId) {
      const savedOrder = orders.find(o => o.razorpayOrderId === razorpayOrderId);

      if (savedOrder) {
        if (event.event === "payment.captured") {
          savedOrder.status = "captured";
          savedOrder.capturedAt = new Date().toISOString();
        }
        if (event.event === "payment.failed") {
          savedOrder.status = "payment_failed";
        }
        writeOrders(orders);
      }
    }

    return res.status(200).json({ received: true });
  }
);

app.get("/profile.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get("/checkout.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "checkout.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Plantia running at http://localhost:${PORT}`);
});
