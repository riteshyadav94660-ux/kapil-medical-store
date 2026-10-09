import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import Razorpay from "razorpay";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  console.error("SESSION_SECRET is required in production");
  process.exit(1);
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));

app.use(session({
  name: "kapil.sid",
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_BEFORE_DEPLOYMENT",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Keep your existing database. Never delete it to update the website.
const db = new Database(path.join(__dirname, "kapil-medical.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  prescription_required INTEGER NOT NULL DEFAULT 0,
  image_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  pincode TEXT NOT NULL DEFAULT '',
  payment_method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  total INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  customer_id INTEGER
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT NOT NULL,
  unit_price INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  razorpay_payment_id TEXT UNIQUE NOT NULL,
  razorpay_order_id TEXT NOT NULL,
  order_id INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id)
);
`);

// Additive migrations preserve existing orders and products.
const orderColumns = db.prepare("PRAGMA table_info(orders)").all();

if (!orderColumns.some(c => c.name === "pincode"))
  db.exec("ALTER TABLE orders ADD COLUMN pincode TEXT NOT NULL DEFAULT ''");

if (!orderColumns.some(c => c.name === "tracking_token_hash"))
  db.exec("ALTER TABLE orders ADD COLUMN tracking_token_hash TEXT");

if (!orderColumns.some(c => c.name === "stock_restored"))
  db.exec("ALTER TABLE orders ADD COLUMN stock_restored INTEGER NOT NULL DEFAULT 0");

if (!orderColumns.some(c => c.name === "customer_id"))
  db.exec("ALTER TABLE orders ADD COLUMN customer_id INTEGER");

const productColumns = db.prepare("PRAGMA table_info(products)").all();

if (!productColumns.some(c => c.name === "image_url"))
  db.exec("ALTER TABLE products ADD COLUMN image_url TEXT NOT NULL DEFAULT ''");

const razorpay =
  process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET
      })
    : null;

// Set ADMIN_USERNAME and ADMIN_PASSWORD in Render.
const username = process.env.ADMIN_USERNAME || "admin";
const password = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";

const existingAdmin = db.prepare("SELECT id FROM admins LIMIT 1").get();

if (!existingAdmin) {
  db.prepare(
    "INSERT INTO admins(username,password_hash) VALUES(?,?)"
  ).run(username, bcrypt.hashSync(password, 12));
} else if (process.env.RESET_ADMIN === "true") {
  db.prepare(
    "UPDATE admins SET username=?,password_hash=? WHERE id=?"
  ).run(username, bcrypt.hashSync(password, 12), existingAdmin.id);
}

// Seed products only when the product table is empty.
if (!db.prepare("SELECT 1 FROM products LIMIT 1").get()) {
  const insert = db.prepare(
    "INSERT INTO products(name,category,price,stock,prescription_required) VALUES(?,?,?,?,?)"
  );

  [
    ["Paracetamol 500mg", "Medicine", 25, 50, 1],
    ["Vitamin C Tablets", "Medicine", 20, 30, 0],
    ["Antiseptic Cream", "Medicine", 85, 25, 0],
    ["Face Wash", "Cosmetics", 199, 20, 0],
    ["Moisturizing Cream", "Cosmetics", 249, 18, 0],
    ["Sunscreen SPF 50", "Cosmetics", 349, 15, 0]
  ].forEach(row => insert.run(...row));
}

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

const requireAdmin = (req, res, next) =>
  req.session.admin
    ? next()
    : res.status(401).json({ error: "Authentication required" });

const text = (value, max = 500) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

// ----------------------------------------------------
// ADMIN LOGIN
// ----------------------------------------------------

app.post(
  "/api/login",
  rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }),
  async (req, res) => {
    const admin = db.prepare(
      "SELECT * FROM admins WHERE username=?"
    ).get(text(req.body?.username, 100));

    if (
      !admin ||
      !(await bcrypt.compare(req.body?.password || "", admin.password_hash))
    ) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: "Unable to start admin session"
        });
      }

      req.session.admin = {
        id: admin.id,
        username: admin.username
      };

      req.session.save(error => {
        if (error) {
          return res.status(500).json({
            error: "Unable to save admin session"
          });
        }

        res.json({ ok: true, username: admin.username });
      });
    });
  }
);

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("kapil.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    authenticated: !!req.session.admin,
    username: req.session.admin?.username || null
  });
});

// ----------------------------------------------------
// PUBLIC PRODUCT LIST
// Includes image_url so customer page can display images.
// ----------------------------------------------------

app.get("/api/products", (req, res) => {
  res.set("Cache-Control", "no-store");

  res.json(db.prepare(`
    SELECT id,name,category,price,stock,prescription_required,image_url
    FROM products
    ORDER BY id DESC
  `).all());
});

// ----------------------------------------------------
// ORDER HELPERS
// ----------------------------------------------------

function parseCustomerAndItems(body) {
  const customer = body.customer || body;

  const data = {
    name: text(customer.name ?? customer.customer_name, 100),
    phone: text(customer.phone, 20),
    address: text(customer.address, 500),
    pincode: text(customer.pincode, 10),
    items: body.items
  };

  if (
    !data.name ||
    !/^[6-9]\d{9}$/.test(data.phone) ||
    !data.address ||
    !/^\d{6}$/.test(data.pincode)
  ) {
    throw Error(
      "Valid name, 10-digit mobile, address and 6-digit pincode are required"
    );
  }

  if (!Array.isArray(data.items) || !data.items.length) {
    throw Error("Order items are missing");
  }

  return data;
}

function calculateItems(items) {
  const quantities = new Map();

  for (const item of items) {
    const id = Number(item.productId ?? item.product_id ?? item.id);
    const quantity = Number(item.quantity ?? 1);

    if (
      !Number.isSafeInteger(id) || id < 1 ||
      !Number.isSafeInteger(quantity) ||
      quantity < 1 || quantity > 99
    ) {
      throw Error("Invalid product or quantity");
    }

    quantities.set(id, (quantities.get(id) || 0) + quantity);
  }

  let total = 0;
  const lines = [];

  for (const [id, quantity] of quantities) {
    if (quantity > 99) throw Error("Maximum quantity exceeded");

    const product = db.prepare(
      "SELECT * FROM products WHERE id=?"
    ).get(id);

    if (!product) throw Error("A product in your cart no longer exists");

    if (product.stock < quantity) {
      throw Error(`Insufficient stock for ${product.name}`);
    }

    if (product.prescription_required) {
      throw Error(
        `${product.name} requires prescription verification before dispensing`
      );
    }

    total += product.price * quantity;
    lines.push({ product, quantity });
  }

  if (!Number.isSafeInteger(total) || total <= 0) {
    throw Error("Invalid order total");
  }

  return { total, lines };
}

const createOrder = db.transaction(
  (data, paymentId = null, razorpayOrderId = null) => {
    const { total, lines } = calculateItems(data.items);

    const trackingToken = crypto.randomBytes(32).toString("hex");
    const trackingHash = crypto
      .createHash("sha256")
      .update(trackingToken)
      .digest("hex");

    const result = db.prepare(`
      INSERT INTO orders
      (customer_name,phone,address,pincode,payment_method,status,total,
       tracking_token_hash,stock_restored,customer_id)
      VALUES(?,?,?,?,?,?,?,?,0,?)
    `).run(
      data.name,
      data.phone,
      data.address,
      data.pincode,
      data.paymentMethod,
      "Pending",
      total,
      trackingHash,
      data.customerId || null
    );

    const orderId = Number(result.lastInsertRowid);

    const updateStock = db.prepare(
      "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?"
    );

    const insertItem = db.prepare(`
      INSERT INTO order_items
      (order_id,product_id,product_name,unit_price,quantity)
      VALUES(?,?,?,?,?)
    `);

    for (const { product, quantity } of lines) {
      if (
        updateStock.run(quantity, product.id, quantity).changes !== 1
      ) {
        throw Error(`Stock changed for ${product.name}; please retry`);
      }

      insertItem.run(
        orderId,
        product.id,
        product.name,
        product.price,
        quantity
      );
    }

    if (paymentId) {
      db.prepare(`
        INSERT INTO payments(razorpay_payment_id,razorpay_order_id,order_id)
        VALUES(?,?,?)
      `).run(paymentId, razorpayOrderId, orderId);
    }

    return { orderId, total, trackingToken };
  }
);

// ----------------------------------------------------
// CASH ON DELIVERY CHECKOUT
// ----------------------------------------------------

app.post("/api/orders", (req, res) => {
  try {
    if (String(req.body?.payment_method || "").toUpperCase() !== "COD") {
      return res.status(400).json({
        error: "Select Cash on Delivery or use online checkout"
      });
    }

    const data = parseCustomerAndItems(req.body);

    if (req.session.customer) {
      const account = db.prepare(
        "SELECT id,phone FROM customers WHERE id=?"
      ).get(req.session.customer.id);

      if (!account || account.phone !== data.phone) {
        return res.status(400).json({
          error: "When signed in, use the mobile number on your customer account."
        });
      }

      data.customerId = account.id;
    }

    const saved = createOrder({
      ...data,
      paymentMethod: "COD"
    });

    res.status(201).json({
      ok: true,
      id: saved.orderId,
      orderId: saved.orderId,
      total: saved.total,
      status: "Pending",
      trackingToken: saved.trackingToken,
      message: "COD order placed successfully"
    });
  } catch (error) {
    console.error("COD order error:", error);
    res.status(400).json({
      error: error.message || "Could not place COD order"
    });
  }
});

// ----------------------------------------------------
// RAZORPAY ORDER CREATION
// ----------------------------------------------------

app.post("/api/razorpay/order", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Online payment is not configured"
      });
    }

    const rupees = Number(req.body?.amount);

    if (
      !Number.isSafeInteger(rupees) ||
      rupees <= 0 ||
      !Number.isSafeInteger(rupees * 100)
    ) {
      return res.status(400).json({
        error: "Invalid amount; expected whole rupees"
      });
    }

    const order = await razorpay.orders.create({
      amount: rupees * 100,
      currency: "INR",
      receipt: "km_" + Date.now()
    });

    res.json({
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error("Razorpay create order error:", error);
    res.status(500).json({
      error: "Unable to create payment order"
    });
  }
});

// ----------------------------------------------------
// RAZORPAY PAYMENT VERIFICATION
// ----------------------------------------------------

app.post("/api/razorpay/verify", async (req, res) => {
  try {
    if (!razorpay || !process.env.RAZORPAY_KEY_SECRET) {
      return res.status(503).json({
        error: "Payment verification is not configured"
      });
    }

    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body || {};

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        error: "Missing payment details"
      });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest();

    const supplied = Buffer.from(String(razorpay_signature), "hex");

    if (
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(expected, supplied)
    ) {
      return res.status(400).json({
        error: "Payment verification failed"
      });
    }

    const payment = await razorpay.payments.fetch(razorpay_payment_id);

    if (
      payment.order_id !== razorpay_order_id ||
      payment.status !== "captured"
    ) {
      return res.status(400).json({
        error: "Payment is not captured"
      });
    }

    const existing = db.prepare(`
      SELECT o.id,o.total
      FROM payments p
      JOIN orders o ON o.id=p.order_id
      WHERE p.razorpay_payment_id=?
    `).get(razorpay_payment_id);

    if (existing) {
      return res.json({
        ok: true,
        verified: true,
        orderId: existing.id,
        total: existing.total,
        trackingToken: null,
        message: "Payment already recorded."
      });
    }

    const data = parseCustomerAndItems(req.body || {});
    const calculated = calculateItems(data.items);

    if (payment.amount !== calculated.total * 100) {
      return res.status(400).json({
        error: "Paid amount does not match the current cart total."
      });
    }

    if (req.session.customer) {
      const account = db.prepare(
        "SELECT id,phone FROM customers WHERE id=?"
      ).get(req.session.customer.id);

      if (!account || account.phone !== data.phone) {
        return res.status(400).json({
          error: "When signed in, use the mobile number on your customer account."
        });
      }

      data.customerId = account.id;
    }

    const saved = createOrder(
      { ...data, paymentMethod: "Razorpay" },
      razorpay_payment_id,
      razorpay_order_id
    );

    res.json({
      ok: true,
      verified: true,
      orderId: saved.orderId,
      total: saved.total,
      trackingToken: saved.trackingToken,
      message: "Payment verified and order saved"
    });
  } catch (error) {
    console.error("Razorpay verification error:", error);
    res.status(400).json({
      error: error.message || "Payment verification or order saving failed"
    });
  }
});

// ----------------------------------------------------
// PRIVATE ORDER TRACKING
// ----------------------------------------------------

app.get("/api/track/:id", (req, res) => {
  try {
    const id = Number(req.params.id);
    const token = String(req.query.token || "");

    if (
      !Number.isSafeInteger(id) ||
      id < 1 ||
      !/^[a-f0-9]{64}$/.test(token)
    ) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = db.prepare(`
      SELECT id,status,created_at,total,payment_method,tracking_token_hash
      FROM orders WHERE id=?
    `).get(id);

    if (!order || !order.tracking_token_hash) {
      return res.status(404).json({ error: "Order not found" });
    }

    const supplied = crypto.createHash("sha256").update(token).digest();
    const stored = Buffer.from(order.tracking_token_hash, "hex");

    if (
      stored.length !== supplied.length ||
      !crypto.timingSafeEqual(stored, supplied)
    ) {
      return res.status(404).json({ error: "Order not found" });
    }

    const items = db.prepare(`
      SELECT product_name,unit_price,quantity
      FROM order_items WHERE order_id=?
    `).all(id);

    res.set("Cache-Control", "no-store");
    res.json({
      orderId: order.id,
      status: order.status,
      createdAt: order.created_at,
      total: order.total,
      paymentMethod: order.payment_method,
      items
    });
  } catch (error) {
    console.error("Tracking error:", error);
    res.status(500).json({
      error: "Unable to retrieve order status"
    });
  }
});

// ----------------------------------------------------
// CUSTOMER ACCOUNT HELPERS
// ----------------------------------------------------

const customerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8
});

function validCustomerPhone(phone) {
  return /^[6-9]\d{9}$/.test(phone);
}

function customerSafe(customer) {
  return {
    id: customer.id,
    name: customer.name,
    phone: customer.phone,
    createdAt: customer.created_at
  };
}

function setCustomerSession(req, res, customer) {
  const admin = req.session.admin || null;

  req.session.regenerate(error => {
    if (error) {
      return res.status(500).json({
        error: "Unable to start customer session"
      });
    }

    if (admin) req.session.admin = admin;

    req.session.customer = {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    };

    req.session.save(err => {
      if (err) {
        return res.status(500).json({
          error: "Unable to save customer session"
        });
      }

      res.json({
        ok: true,
        customer: customerSafe(customer)
      });
    });
  });
}

// Password registration retained for compatibility.
app.post("/api/customer/register", customerLimiter, async (req, res) => {
  try {
    const name = text(req.body?.name, 100);
    const phone = text(req.body?.phone, 20);
    const password = typeof req.body?.password === "string"
      ? req.body.password : "";

    if (
      !name ||
      !validCustomerPhone(phone) ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Enter your name, valid mobile number and password of 8–128 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO customers(name,phone,password_hash)
      VALUES(?,?,?)
    `).run(name, phone, hash);

    const customer = db.prepare(`
      SELECT id,name,phone,created_at FROM customers WHERE id=?
    `).get(Number(result.lastInsertRowid));

    setCustomerSession(req, res, customer);
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({
        error: "An account with this mobile number already exists. Please sign in."
      });
    }

    console.error("Customer registration error:", error);
    res.status(400).json({ error: "Could not create account." });
  }
});

app.post("/api/customer/login", customerLimiter, async (req, res) => {
  const phone = text(req.body?.phone, 20);
  const password = typeof req.body?.password === "string"
    ? req.body.password : "";

  const customer = db.prepare(
    "SELECT * FROM customers WHERE phone=?"
  ).get(phone);

  if (
    !customer ||
    !(await bcrypt.compare(password, customer.password_hash))
  ) {
    return res.status(401).json({
      error: "Invalid mobile number or password."
    });
  }

  setCustomerSession(req, res, customer);
});

app.get("/api/customer/me", (req, res) => {
  if (!req.session.customer) {
    return res.json({ authenticated: false, customer: null });
  }

  const customer = db.prepare(`
    SELECT id,name,phone,created_at FROM customers WHERE id=?
  `).get(req.session.customer.id);

  if (!customer) {
    delete req.session.customer;
    return res.json({ authenticated: false, customer: null });
  }

  res.set("Cache-Control", "no-store");
  res.json({
    authenticated: true,
    customer: customerSafe(customer)
  });
});

app.post("/api/customer/logout", (req, res) => {
  delete req.session.customer;

  req.session.save(error => {
    if (error) {
      return res.status(500).json({ error: "Unable to sign out" });
    }

    res.json({ ok: true });
  });
});

app.get("/api/customer/orders", (req, res) => {
  if (!req.session.customer) {
    return res.status(401).json({
      error: "Please sign in to view your orders."
    });
  }

  const orders = db.prepare(`
    SELECT id,status,created_at,total,payment_method
    FROM orders
    WHERE customer_id=?
    ORDER BY id DESC
  `).all(req.session.customer.id);

  const getItems = db.prepare(`
    SELECT product_id,product_name,unit_price,quantity
    FROM order_items WHERE order_id=?
  `);

  res.set("Cache-Control", "no-store");
  res.json(orders.map(order => ({
    ...order,
    items: getItems.all(order.id)
  })));
});

// ----------------------------------------------------
// MSG91 OTP CONFIGURATION AND TOKEN VERIFICATION
// ----------------------------------------------------

app.get("/api/msg91/config", (req, res) => {
  if (!process.env.MSG91_WIDGET_TOKEN_AUTH) {
    return res.status(503).json({
      error: "OTP login is not configured yet."
    });
  }

  res.set("Cache-Control", "no-store");

  res.json({
    widgetId: "366a6968376e383936323435",
    tokenAuth: process.env.MSG91_WIDGET_TOKEN_AUTH
  });
});

app.post("/api/customer/otp-login", customerLimiter, async (req, res) => {
  try {
    const accessToken = text(req.body?.accessToken, 4000);
    const suppliedName = text(req.body?.name, 100);

    if (!accessToken) {
      return res.status(400).json({
        error: "Complete OTP verification first."
      });
    }

    if (!process.env.MSG91_AUTH_KEY) {
      return res.status(503).json({
        error: "OTP verification is not configured on the server."
      });
    }

    const response = await fetch(
      "https://control.msg91.com/api/v5/widget/verifyAccessToken",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({
          authkey: process.env.MSG91_AUTH_KEY,
          "access-token": accessToken
        }),
        signal: AbortSignal.timeout(10000)
      }
    );

    const verification = await response.json().catch(() => ({}));

    if (!response.ok) {
      console.error("MSG91 token verification rejected:", response.status);
      return res.status(401).json({
        error: "OTP verification failed. Please try again."
      });
    }

    // Never trust a phone number claimed only by the browser.
    // Confirm these response fields match your actual MSG91 response.
    const rawPhone =
      verification?.data?.mobile ||
      verification?.data?.phone ||
      verification?.mobile ||
      verification?.phone ||
      verification?.identifier ||
      verification?.data?.identifier ||
      "";

    const phone = String(rawPhone)
      .replace(/^\+91/, "")
      .replace(/\D/g, "")
      .slice(-10);

    if (!validCustomerPhone(phone)) {
      console.error(
        "MSG91 response did not contain a supported verified phone field"
      );

      return res.status(401).json({
        error: "MSG91 token response needs verification before OTP login can be enabled."
      });
    }

    let customer = db.prepare(`
      SELECT id,name,phone,created_at FROM customers WHERE phone=?
    `).get(phone);

    if (!customer) {
      if (!suppliedName) {
        return res.status(400).json({
          error: "Enter your name to create your first account."
        });
      }

      const randomPasswordHash = await bcrypt.hash(
        crypto.randomBytes(32).toString("hex"),
        12
      );

      try {
        const result = db.prepare(`
          INSERT INTO customers(name,phone,password_hash)
          VALUES(?,?,?)
        `).run(suppliedName, phone, randomPasswordHash);

        customer = db.prepare(`
          SELECT id,name,phone,created_at FROM customers WHERE id=?
        `).get(Number(result.lastInsertRowid));
      } catch (error) {
        if (!String(error.message).includes("UNIQUE")) throw error;

        customer = db.prepare(`
          SELECT id,name,phone,created_at FROM customers WHERE phone=?
        `).get(phone);
      }
    }

    if (!customer) {
      return res.status(500).json({
        error: "Unable to load customer account."
      });
    }

    setCustomerSession(req, res, customer);
  } catch (error) {
    console.error("MSG91 OTP login error:", error.message);

    res.status(502).json({
      error: "Could not verify OTP right now. Please try again."
    });
  }
});

// ----------------------------------------------------
// ADMIN CUSTOMER LIST
// ----------------------------------------------------

app.get("/api/admin/customers", requireAdmin, (req, res) => {
  res.set("Cache-Control", "no-store");

  const customers = db.prepare(`
    SELECT
      c.id,
      c.name,
      c.phone,
      c.created_at,
      COUNT(o.id) AS order_count,
      COALESCE(
        SUM(CASE WHEN o.status='Delivered' THEN o.total ELSE 0 END),
        0
      ) AS delivered_total
    FROM customers c
    LEFT JOIN orders o ON o.customer_id=c.id
    GROUP BY c.id
    ORDER BY c.id DESC
  `).all();

  res.json(customers);
});

// ----------------------------------------------------
// ADMIN ORDER LIST AND STATUS UPDATES
// ----------------------------------------------------

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT id,customer_name,phone,address,pincode,payment_method,
           status,total,created_at
    FROM orders
    ORDER BY id DESC
  `).all();

  const getItems = db.prepare(
    "SELECT * FROM order_items WHERE order_id=?"
  );

  res.set("Cache-Control", "no-store");

  res.json(orders.map(order => ({
    ...order,
    items: getItems.all(order.id)
  })));
});

app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.status;

  const allowed = [
    "Pending",
    "Confirmed",
    "Shipped",
    "Delivered",
    "Cancelled"
  ];

  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    !allowed.includes(status)
  ) {
    return res.status(400).json({
      error: "Invalid order or status"
    });
  }

  try {
    const update = db.transaction(() => {
      const order = db.prepare(`
        SELECT id,status,stock_restored
        FROM orders WHERE id=?
      `).get(id);

      if (!order) throw Error("Order not found");

      if (order.status === "Cancelled" && status !== "Cancelled") {
        throw Error("Cancelled orders cannot be reopened.");
      }

      if (order.status === "Delivered" && status === "Cancelled") {
        throw Error("Delivered orders cannot be cancelled from this panel.");
      }

      if (
        status === "Cancelled" &&
        order.status !== "Cancelled" &&
        order.stock_restored !== 1
      ) {
        const items = db.prepare(`
          SELECT product_id,quantity
          FROM order_items WHERE order_id=?
        `).all(id);

        const restore = db.prepare(
          "UPDATE products SET stock=stock+? WHERE id=?"
        );

        for (const item of items) {
          if (restore.run(item.quantity, item.product_id).changes !== 1) {
            throw Error("Could not restore inventory for an order item");
          }
        }

        db.prepare(
          "UPDATE orders SET stock_restored=1 WHERE id=?"
        ).run(id);
      }

      db.prepare(
        "UPDATE orders SET status=? WHERE id=?"
      ).run(status, id);

      return { ok: true, id, status };
    });

    res.json(update());
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ----------------------------------------------------
// ADMIN PRODUCTS AND IMAGE URL MANAGEMENT
// ----------------------------------------------------

app.get("/api/admin/products", requireAdmin, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM products ORDER BY id DESC").all()
  );
});

function validImageUrl(value) {
  const raw = text(value, 1500);

  if (!raw) return "";

  try {
    const url = new URL(raw);
    return url.protocol === "https:" ? url.href : "";
  } catch {
    return "";
  }
}

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const body = req.body || {};

  const name = text(body.name, 150);
  const category = text(body.category, 80);
  const price = Number(body.price);
  const stock = Number(body.stock);
  const imageUrl = validImageUrl(body.image_url);

  if (
    !name ||
    !category ||
    !Number.isSafeInteger(price) || price < 0 ||
    !Number.isSafeInteger(stock) || stock < 0
  ) {
    return res.status(400).json({
      error: "Enter valid product details"
    });
  }

  if (body.image_url && !imageUrl) {
    return res.status(400).json({
      error: "Product image must be a valid HTTPS image URL."
    });
  }

  const result = db.prepare(`
    INSERT INTO products
    (name,category,price,stock,prescription_required,image_url)
    VALUES(?,?,?,?,?,?)
  `).run(
    name,
    category,
    price,
    stock,
    body.prescription_required ? 1 : 0,
    imageUrl
  );

  res.status(201).json({
    ok: true,
    id: Number(result.lastInsertRowid)
  });
});

app.patch("/api/admin/products/:id", requireAdmin, (req, res) => {
  const body = req.body || {};

  const name = text(body.name, 150);
  const category = text(body.category, 80);
  const price = Number(body.price);
  const stock = Number(body.stock);
  const id = Number(req.params.id);
  const imageUrl = validImageUrl(body.image_url);

  if (
    !Number.isSafeInteger(id) || id < 1 ||
    !name ||
    !category ||
    !Number.isSafeInteger(price) || price < 0 ||
    !Number.isSafeInteger(stock) || stock < 0
  ) {
    return res.status(400).json({
      error: "Enter valid product details"
    });
  }

  if (body.image_url && !imageUrl) {
    return res.status(400).json({
      error: "Product image must be a valid HTTPS image URL."
    });
  }

  const result = db.prepare(`
    UPDATE products
    SET name=?,category=?,price=?,stock=?,prescription_required=?,image_url=?
    WHERE id=?
  `).run(
    name,
    category,
    price,
    stock,
    body.prescription_required ? 1 : 0,
    imageUrl,
    id
  );

  if (!result.changes) {
    return res.status(404).json({ error: "Product not found" });
  }

  res.json({ ok: true });
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid product ID" });
  }

  // Preserve historical order items.
  const used = db.prepare(
    "SELECT 1 FROM order_items WHERE product_id=? LIMIT 1"
  ).get(id);

  if (used) {
    return res.status(409).json({
      error: "This product appears in order history. Set its stock to 0 instead of deleting it."
    });
  }

  const result = db.prepare(
    "DELETE FROM products WHERE id=?"
  ).run(id);

  if (!result.changes) {
    return res.status(404).json({ error: "Product not found" });
  }

  res.json({ ok: true });
});

// ----------------------------------------------------
// PAGES
// ----------------------------------------------------

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Secure order tracking page.
app.get("/track", (req, res) => {
  res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Track Order | Kapil Medical</title>
<style>
body{margin:0;background:#f4f8f5;color:#20312a;font:16px Arial,sans-serif}
main{max-width:650px;margin:35px auto;padding:18px}
.card{background:white;padding:24px;border:1px solid #dce8e0;border-radius:16px}
h1{color:#087f5b;font-size:25px}
.muted{color:#65746b;line-height:1.5}
.status{display:inline-block;background:#e3f5e9;color:#07523e;border-radius:30px;padding:9px 14px;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-top:20px}
td,th{text-align:left;padding:11px 5px;border-bottom:1px solid #e4ece6}
input,button{padding:12px;border-radius:8px;font:inherit}
input{width:100%;box-sizing:border-box;border:1px solid #cbd8cf;margin:8px 0}
button{background:#087f5b;color:white;border:0;cursor:pointer}
.total{font-size:21px;font-weight:bold;text-align:right;margin-top:20px}
.error{color:#b42318}
</style>
</head>
<body>
<main>
<div class="card">
<h1>💚 Kapil Medical</h1>
<p class="muted">Secure order tracking</p>
<form id="lookup">
<label>Order ID
<input id="orderId" type="number" min="1" required>
</label>
<label>Private tracking token
<input id="token" required minlength="64" maxlength="64"
pattern="[a-fA-F0-9]{64}" autocomplete="off">
</label>
<button type="submit">Track order</button>
</form>
<p id="message" class="muted" role="status"></p>
<section id="result" hidden>
<h2 id="heading"></h2>
<p>Order status: <span id="status" class="status"></span></p>
<p id="details" class="muted"></p>
<table>
<thead><tr><th>Item</th><th>Qty</th><th>Price</th></tr></thead>
<tbody id="items"></tbody>
</table>
<p id="total" class="total"></p>
<p class="muted">Keep your private tracking link confidential.</p>
</section>
</div>
</main>
<script>
const $=id=>document.getElementById(id);
const params=new URLSearchParams(location.search);
if(params.has("order"))$("orderId").value=params.get("order");
if(params.has("token"))$("token").value=params.get("token");

$("lookup").addEventListener("submit",async e=>{
  e.preventDefault();
  $("result").hidden=true;
  $("message").textContent="Checking order…";

  try{
    const response=await fetch(
      "/api/track/"+encodeURIComponent($("orderId").value)+
      "?token="+encodeURIComponent($("token").value.trim()),
      {headers:{Accept:"application/json"},cache:"no-store"}
    );
    const data=await response.json();

    if(!response.ok)throw Error(data.error||"Order not found");

    $("heading").textContent="Order #"+data.orderId;
    $("status").textContent=data.status;
    $("details").textContent="Placed: "+data.createdAt+
      " · Payment: "+data.paymentMethod;
    $("items").replaceChildren();

    (data.items||[]).forEach(item=>{
      const row=document.createElement("tr");

      [
        item.product_name,
        item.quantity,
        "₹"+Number(item.unit_price).toLocaleString("en-IN")
      ].forEach(value=>{
        const cell=document.createElement("td");
        cell.textContent=value;
        row.appendChild(cell);
      });

      $("items").appendChild(row);
    });

    $("total").textContent="Total: ₹"+
      Number(data.total).toLocaleString("en-IN");
    $("result").hidden=false;
    $("message").textContent="";
  }catch(error){
    $("message").textContent=error.message;
    $("message").className="error";
  }
});
</script>
</body>
</html>`);
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API endpoint not found" });
  }

  res.status(404).send("Page not found");
});

app.listen(PORT, () => {
  console.log("Kapil Medical running on port " + PORT);
});
