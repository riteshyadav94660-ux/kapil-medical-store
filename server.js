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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be configured in production.");
}

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));

app.use(session({
  name: "kapil.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProduction,
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const db = new Database(path.join(__dirname, "kapil-medical.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'General',
    price REAL NOT NULL,
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
    payment_method TEXT NOT NULL DEFAULT 'COD',
    status TEXT NOT NULL DEFAULT 'Placed',
    total REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    customer_id INTEGER,
    tracking_token_hash TEXT,
    stock_restored INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(customer_id) REFERENCES customers(id)
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER,
    product_name TEXT NOT NULL,
    unit_price REAL NOT NULL,
    quantity INTEGER NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    razorpay_payment_id TEXT NOT NULL UNIQUE,
    razorpay_order_id TEXT NOT NULL,
    order_id INTEGER NOT NULL,
    FOREIGN KEY(order_id) REFERENCES orders(id)
  );
`);

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some(item => item.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

// Safe, additive migrations. Existing rows are preserved.
ensureColumn("products", "image_url", "TEXT NOT NULL DEFAULT ''");
ensureColumn("orders", "pincode", "TEXT NOT NULL DEFAULT ''");
ensureColumn("orders", "tracking_token_hash", "TEXT");
ensureColumn("orders", "stock_restored", "INTEGER NOT NULL DEFAULT 0");
ensureColumn("orders", "customer_id", "INTEGER");

const text = (value, max = 500) =>
  typeof value === "string" ? value.trim().slice(0, max) : "";

const number = value => {
  const result = Number(value);
  return Number.isFinite(result) ? result : NaN;
};

function validImageUrl(value) {
  if (typeof value !== "string") return "";
  const raw = value.trim();

  try {
    const url = new URL(raw);
    if (url.protocol === "https:") return url.href;
  } catch {}

  const match = raw.match(
    /^data:image\/(jpeg|png|webp|gif);base64,([A-Za-z0-9+/]+={0,2})$/
  );

  if (!match) return "";

  const bytes = Buffer.from(match[2], "base64");
  if (!bytes.length || bytes.length > 1024 * 1024) return "";

  return raw;
}

function normalizePhone(value) {
  const digits = String(value || "").replace(/\D/g, "");
  if (digits.length === 12 && digits.startsWith("91")) {
    return digits.slice(2);
  }
  return digits;
}

function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function requireAdmin(req, res, next) {
  if (!req.session?.admin) {
    return res.status(401).json({ error: "Please sign in as admin." });
  }
  next();
}

function requireCustomer(req, res, next) {
  if (!req.session?.customer) {
    return res.status(401).json({ error: "Please sign in to continue." });
  }
  next();
}

function customerLimiter(req, res, next) {
  next();
}

function setCustomerSession(req, res, customer) {
  req.session.regenerate(error => {
    if (error) {
      console.error("Session regeneration failed:", error);
      return res.status(500).json({ error: "Could not create session." });
    }

    req.session.customer = {
      id: customer.id,
      name: customer.name,
      phone: customer.phone
    };

    req.session.save(saveError => {
      if (saveError) {
        console.error("Session save failed:", saveError);
        return res.status(500).json({ error: "Could not save session." });
      }

      res.json({
        ok: true,
        customer: req.session.customer
      });
    });
  });
}

function getCustomer(req) {
  if (!req.session?.customer) return null;

  return db.prepare(`
    SELECT id, name, phone, created_at
    FROM customers
    WHERE id = ?
  `).get(req.session.customer.id) || null;
}

function productById(id) {
  return db.prepare(`
    SELECT id, name, category, price, stock,
           prescription_required, image_url
    FROM products
    WHERE id = ?
  `).get(id);
}

function validateProductFields(body) {
  const name = text(body?.name, 150);
  const category = text(body?.category, 100) || "General";
  const price = number(body?.price);
  const stock = number(body?.stock);
  const prescriptionRequired = body?.prescription_required ? 1 : 0;
  const imageUrl = validImageUrl(body?.image_url);

  if (!name) throw new Error("Product name is required.");
  if (!Number.isFinite(price) || price < 0) {
    throw new Error("Enter a valid product price.");
  }
  if (!Number.isInteger(stock) || stock < 0) {
    throw new Error("Enter a valid stock quantity.");
  }
  if (body?.image_url && !imageUrl) {
    throw new Error("Invalid image. Use an HTTPS image URL or an image under 1 MB.");
  }

  return {
    name,
    category,
    price,
    stock,
    prescriptionRequired,
    imageUrl
  };
}

function validateOrderDetails(body) {
  const customerName = text(body?.customerName || body?.customer_name, 100);
  const phone = normalizePhone(body?.phone);
  const address = text(body?.address, 500);
  const pincode = text(body?.pincode, 10);

  if (!customerName) throw new Error("Customer name is required.");
  if (!/^[6-9]\d{9}$/.test(phone)) {
    throw new Error("Enter a valid 10-digit mobile number.");
  }
  if (!address) throw new Error("Delivery address is required.");
  if (pincode && !/^\d{6}$/.test(pincode)) {
    throw new Error("Enter a valid 6-digit PIN code.");
  }

  return { customerName, phone, address, pincode };
}

function calculateItems(items) {
  if (!Array.isArray(items) || !items.length || items.length > 50) {
    throw new Error("Your cart is empty or invalid.");
  }

  const combined = new Map();

  for (const item of items) {
    const productId = Number(item.productId ?? item.product_id ?? item.id);
    const quantity = Number(item.quantity);

    if (!Number.isInteger(productId) || productId < 1) {
      throw new Error("Invalid product in cart.");
    }
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 99) {
      throw new Error("Invalid product quantity.");
    }

    combined.set(productId, (combined.get(productId) || 0) + quantity);
  }

  const result = [];
  let total = 0;

  for (const [productId, quantity] of combined) {
    const product = productById(productId);

    if (!product) throw new Error("A product in your cart no longer exists.");
    if (product.stock < quantity) {
      throw new Error(`Not enough stock for ${product.name}.`);
    }
    if (product.prescription_required) {
      throw new Error(
        `${product.name} requires prescription verification and cannot be ordered through this checkout.`
      );
    }

    total += product.price * quantity;

    result.push({
      productId: product.id,
      name: product.name,
      price: product.price,
      quantity
    });
  }

  return { items: result, total: Math.round(total * 100) / 100 };
}

function createOrder({ details, items, total, paymentMethod, customerId = null }) {
  const token = crypto.randomBytes(32).toString("hex");

  const insertOrder = db.prepare(`
    INSERT INTO orders
      (customer_name, phone, address, pincode, payment_method,
       status, total, customer_id, tracking_token_hash)
    VALUES (?, ?, ?, ?, ?, 'Placed', ?, ?, ?)
  `);

  const insertItem = db.prepare(`
    INSERT INTO order_items
      (order_id, product_id, product_name, unit_price, quantity)
    VALUES (?, ?, ?, ?, ?)
  `);

  const decreaseStock = db.prepare(`
    UPDATE products SET stock = stock - ?
    WHERE id = ? AND stock >= ?
  `);

  const transaction = db.transaction(() => {
    const order = insertOrder.run(
      details.customerName,
      details.phone,
      details.address,
      details.pincode,
      paymentMethod,
      total,
      customerId,
      hashToken(token)
    );

    const orderId = Number(order.lastInsertRowid);

    for (const item of items) {
      const update = decreaseStock.run(
        item.quantity,
        item.productId,
        item.quantity
      );

      if (!update.changes) {
        throw new Error(`Stock changed for ${item.name}. Please retry.`);
      }

      insertItem.run(
        orderId,
        item.productId,
        item.name,
        item.price,
        item.quantity
      );
    }

    return orderId;
  });

  const orderId = transaction();
  return { orderId, trackingToken: token };
}

// Admin bootstrap: only creates an admin if no admin exists.
const adminCount = db.prepare("SELECT COUNT(*) AS count FROM admins").get().count;

if (!adminCount) {
  const username = text(process.env.ADMIN_USERNAME || "admin", 100);
  const password = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";

  if (password === "CHANGE_ME_NOW" && isProduction) {
    console.warn("Set ADMIN_PASSWORD before using the admin login in production.");
  }

  const passwordHash = bcrypt.hashSync(password, 12);

  db.prepare(`
    INSERT INTO admins(username, password_hash) VALUES (?, ?)
  `).run(username, passwordHash);
}

if (process.env.RESET_ADMIN === "true") {
  const username = text(process.env.ADMIN_USERNAME || "admin", 100);
  const password = process.env.ADMIN_PASSWORD;

  if (!password) {
    throw new Error("Set ADMIN_PASSWORD before using RESET_ADMIN=true.");
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  const firstAdmin = db.prepare("SELECT id FROM admins ORDER BY id LIMIT 1").get();

  if (firstAdmin) {
    db.prepare(`
      UPDATE admins SET username = ?, password_hash = ? WHERE id = ?
    `).run(username, passwordHash, firstAdmin.id);
  } else {
    db.prepare(`
      INSERT INTO admins(username, password_hash) VALUES (?, ?)
    `).run(username, passwordHash);
  }
}

// Seed products only when the products table is empty.
const existingProducts = db.prepare("SELECT COUNT(*) AS count FROM products").get().count;

if (!existingProducts) {
  const seed = db.prepare(`
    INSERT INTO products(name, category, price, stock, prescription_required, image_url)
    VALUES (?, ?, ?, ?, ?, '')
  `);

  const seedTransaction = db.transaction(() => {
    seed.run("Paracetamol 500 mg", "Medicine", 20, 50, 0);
    seed.run("Vitamin C Tablets", "Supplements", 99, 30, 0);
    seed.run("Digital Thermometer", "Healthcare", 150, 15, 0);
    seed.run("Hand Sanitizer", "Personal Care", 60, 25, 0);
    seed.run("Cotton Roll", "First Aid", 35, 20, 0);
    seed.run("Adhesive Bandages", "First Aid", 25, 40, 0);
  });

  seedTransaction();
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

app.use("/api", apiLimiter);

// Admin login
app.post("/api/login", async (req, res) => {
  try {
    const username = text(req.body?.username, 100);
    const password = typeof req.body?.password === "string"
      ? req.body.password
      : "";

    const admin = db.prepare(
      "SELECT id, username, password_hash FROM admins WHERE username = ?"
    ).get(username);

    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({ error: "Could not start admin session." });
      }

      req.session.admin = { id: admin.id, username: admin.username };

      req.session.save(saveError => {
        if (saveError) {
          return res.status(500).json({ error: "Could not save admin session." });
        }

        res.json({ ok: true, admin: req.session.admin });
      });
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("kapil.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    admin: req.session?.admin || null,
    customer: req.session?.customer || null
  });
});

// Customer-facing product list
app.get("/api/products", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(db.prepare(`
    SELECT id, name, category, price, stock,
           prescription_required, image_url
    FROM products
    ORDER BY id DESC
  `).all());
});

// Customer registration
app.post("/api/customer/register", async (req, res) => {
  try {
    const name = text(req.body?.name, 100);
    const phone = normalizePhone(req.body?.phone);
    const password = typeof req.body?.password === "string"
      ? req.body.password
      : "";

    if (!name) return res.status(400).json({ error: "Enter your name." });
    if (!/^[6-9]\d{9}$/.test(phone)) {
      return res.status(400).json({ error: "Enter a valid 10-digit mobile number." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must contain at least 8 characters." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    try {
      const result = db.prepare(`
        INSERT INTO customers(name, phone, password_hash)
        VALUES (?, ?, ?)
      `).run(name, phone, passwordHash);

      const customer = db.prepare(`
        SELECT id, name, phone, created_at FROM customers WHERE id = ?
      `).get(Number(result.lastInsertRowid));

      return setCustomerSession(req, res, customer);
    } catch (error) {
      if (String(error.message).includes("UNIQUE")) {
        return res.status(409).json({ error: "This mobile number is already registered." });
      }
      throw error;
    }
  } catch (error) {
    console.error("Customer registration error:", error);
    res.status(500).json({ error: "Could not create customer account." });
  }
});

// Customer password login
app.post("/api/customer/login", async (req, res) => {
  try {
    const phone = normalizePhone(req.body?.phone);
    const password = typeof req.body?.password === "string"
      ? req.body.password
      : "";

    const customer = db.prepare(`
      SELECT id, name, phone, password_hash, created_at
      FROM customers WHERE phone = ?
    `).get(phone);

    if (!customer || !(await bcrypt.compare(password, customer.password_hash))) {
      return res.status(401).json({ error: "Invalid mobile number or password." });
    }

    return setCustomerSession(req, res, customer);
  } catch (error) {
    console.error("Customer login error:", error);
    res.status(500).json({ error: "Could not sign in." });
  }
});

// MSG91 widget configuration
app.get("/api/msg91/config", (req, res) => {
  const tokenAuth = process.env.MSG91_WIDGET_TOKEN_AUTH;

  if (!tokenAuth || !process.env.MSG91_AUTH_KEY) {
    return res.status(503).json({
      error: "MSG91 OTP is not configured on the server."
    });
  }

  res.set("Cache-Control", "no-store");
  res.json({
    widgetId: "366a6968376e383936323435",
    tokenAuth
  });
});

// MSG91 OTP token verification.
// Confirm the returned phone-number field against your MSG91 account's response format.
app.post("/api/customer/otp-login", async (req, res) => {
  try {
    const accessToken = text(req.body?.accessToken, 3000);
    const name = text(req.body?.name, 100);

    if (!accessToken) {
      return res.status(400).json({ error: "MSG91 access token is missing." });
    }

    if (!process.env.MSG91_AUTH_KEY) {
      return res.status(503).json({ error: "MSG91 is not configured." });
    }

    const response = await fetch(
      "https://control.msg91.com/api/v5/widget/verifyAccessToken",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify({
          authkey: process.env.MSG91_AUTH_KEY,
          "access-token": accessToken
        })
      }
    );

    const result = await response.json().catch(() => ({}));
// Temporary diagnostic: log response structure only, not tokens or phone numbers.
console.log("MSG91 verification response:", {
  httpStatus: response.status,
  topLevelKeys: Object.keys(result || {}),
  dataKeys:
    result?.data && typeof result.data === "object"
      ? Object.keys(result.data)
      : [],
  dataType: typeof result?.data,
  responseType: result?.type,
  responseCode: result?.code
});
    if (!response.ok) {
      console.error("MSG91 verification rejected:", response.status);
      return res.status(401).json({
        error: "MSG91 could not verify the OTP session."
      });
    }

    const candidates = [
      result?.data?.mobile,
      result?.data?.phone,
      result?.mobile,
      result?.phone,
      result?.data?.identifier,
      result?.identifier
    ];

    let phone = "";

    for (const candidate of candidates) {
      if (typeof candidate !== "string") continue;

      const normalized = normalizePhone(candidate);

      if (/^[6-9]\d{9}$/.test(normalized)) {
        phone = normalized;
        break;
      }
    }

    if (!phone) {
      console.error("MSG91 verification response has no recognized phone field.");
      return res.status(401).json({
        error: "Could not identify the verified mobile number in the MSG91 response."
      });
    }

    let customer = db.prepare(`
      SELECT id, name, phone, created_at
      FROM customers WHERE phone = ?
    `).get(phone);

    if (!customer) {
      if (!name) {
        return res.status(400).json({
          error: "Enter your name to create a new customer account."
        });
      }

      const randomPassword = crypto.randomBytes(32).toString("hex");
      const passwordHash = await bcrypt.hash(randomPassword, 12);

      const resultInsert = db.prepare(`
        INSERT INTO customers(name, phone, password_hash)
        VALUES (?, ?, ?)
      `).run(name, phone, passwordHash);

      customer = db.prepare(`
        SELECT id, name, phone, created_at
        FROM customers WHERE id = ?
      `).get(Number(resultInsert.lastInsertRowid));
    }

    return setCustomerSession(req, res, customer);
  } catch (error) {
    console.error("MSG91 OTP login error:", error);
    res.status(500).json({ error: "OTP sign-in failed. Please try again." });
  }
});

app.get("/api/customer/me", (req, res) => {
  const customer = getCustomer(req);
  if (!customer) return res.status(401).json({ error: "Please sign in." });
  res.json({ customer });
});

app.post("/api/customer/logout", (req, res) => {
  delete req.session.customer;
  req.session.save(error => {
    if (error) return res.status(500).json({ error: "Could not sign out." });
    res.json({ ok: true });
  });
});

app.get("/api/customer/orders", requireCustomer, (req, res) => {
  const customer = getCustomer(req);

  if (!customer) {
    return res.status(401).json({ error: "Please sign in again." });
  }

  const orders = db.prepare(`
    SELECT id, customer_name, phone, address, pincode,
           payment_method, status, total, created_at
    FROM orders
    WHERE customer_id = ?
    ORDER BY id DESC
  `).all(customer.id);

  const itemsQuery = db.prepare(`
    SELECT product_name, unit_price, quantity
    FROM order_items WHERE order_id = ?
  `);

  res.json(orders.map(order => ({
    ...order,
    items: itemsQuery.all(order.id)
  })));
});

// Create COD order
app.post("/api/orders", (req, res) => {
  try {
    const details = validateOrderDetails(req.body);
    const calculated = calculateItems(req.body?.items);
    const customerId = req.session?.customer?.id || null;

    const created = createOrder({
      details,
      items: calculated.items,
      total: calculated.total,
      paymentMethod: "COD",
      customerId
    });

    res.status(201).json({
      ok: true,
      orderId: created.orderId,
      total: calculated.total,
      trackingToken: created.trackingToken
    });
  } catch (error) {
    res.status(400).json({ error: error.message || "Could not place order." });
  }
});

// Razorpay setup
function getRazorpay() {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    throw new Error("Razorpay is not configured.");
  }

  return new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });
}

app.get("/api/razorpay/config", (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    return res.status(503).json({ error: "Online payment is not configured." });
  }

  res.json({ keyId: process.env.RAZORPAY_KEY_ID });
});

app.post("/api/razorpay/order", async (req, res) => {
  try {
    const details = validateOrderDetails(req.body);
    const calculated = calculateItems(req.body?.items);

    if (calculated.total <= 0) {
      return res.status(400).json({ error: "Invalid order total." });
    }

    const razorpay = getRazorpay();

    const order = await razorpay.orders.create({
      amount: Math.round(calculated.total * 100),
      currency: "INR",
      receipt: `kapil_${Date.now()}`
    });

    req.session.pendingPayment = {
      razorpayOrderId: order.id,
      details,
      items: calculated.items,
      total: calculated.total,
      customerId: req.session?.customer?.id || null
    };

    res.json({
      ok: true,
      keyId: process.env.RAZORPAY_KEY_ID,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency
    });
  } catch (error) {
    console.error("Razorpay order error:", error);
    res.status(400).json({ error: error.message || "Could not start payment." });
  }
});

app.post("/api/razorpay/verify", (req, res) => {
  try {
    const paymentId = text(req.body?.razorpay_payment_id, 200);
    const orderId = text(req.body?.razorpay_order_id, 200);
    const signature = text(req.body?.razorpay_signature, 500);

    const pending = req.session.pendingPayment;

    if (!pending || pending.razorpayOrderId !== orderId) {
      return res.status(400).json({ error: "Payment session expired. Please retry." });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || "")
      .update(`${orderId}|${paymentId}`)
      .digest("hex");

    const a = Buffer.from(expected);
    const b = Buffer.from(signature);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ error: "Payment signature is invalid." });
    }

    const existing = db.prepare(
      "SELECT order_id FROM payments WHERE razorpay_payment_id = ?"
    ).get(paymentId);

    if (existing) {
      return res.status(409).json({ error: "This payment has already been used." });
    }

    const created = createOrder({
      details: pending.details,
      items: pending.items,
      total: pending.total,
      paymentMethod: "Razorpay",
      customerId: pending.customerId
    });

    db.prepare(`
      INSERT INTO payments(razorpay_payment_id, razorpay_order_id, order_id)
      VALUES (?, ?, ?)
    `).run(paymentId, orderId, created.orderId);

    delete req.session.pendingPayment;

    res.json({
      ok: true,
      orderId: created.orderId,
      total: pending.total,
      trackingToken: created.trackingToken
    });
  } catch (error) {
    console.error("Razorpay verification error:", error);
    res.status(400).json({ error: error.message || "Could not verify payment." });
  }
});

// Public order tracking requires both order ID and secret token.
app.get("/api/track/:id", (req, res) => {
  const id = Number(req.params.id);
  const token = text(req.query.token, 200);

  if (!Number.isInteger(id) || id < 1 || !token) {
    return res.status(400).json({ error: "Tracking details are invalid." });
  }

  const order = db.prepare(`
    SELECT id, status, created_at, payment_method
    FROM orders
    WHERE id = ? AND tracking_token_hash = ?
  `).get(id, hashToken(token));

  if (!order) {
    return res.status(404).json({ error: "Order not found." });
  }

  const items = db.prepare(`
    SELECT product_name, unit_price, quantity
    FROM order_items WHERE order_id = ?
  `).all(id);

  res.json({ ...order, items });
});

// Admin customer list
app.get("/api/admin/customers", requireAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT id, name, phone, created_at
    FROM customers
    ORDER BY id DESC
  `).all());
});

// Admin order list
app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT id, customer_name, phone, address, pincode,
           payment_method, status, total, created_at, customer_id
    FROM orders ORDER BY id DESC
  `).all();

  const itemsQuery = db.prepare(`
    SELECT product_id, product_name, unit_price, quantity
    FROM order_items WHERE order_id = ?
  `);

  res.json(orders.map(order => ({
    ...order,
    items: itemsQuery.all(order.id)
  })));
});

// Admin update order status
app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const status = text(req.body?.status, 50);
  const allowed = [
    "Placed",
    "Confirmed",
    "Processing",
    "Packed",
    "Out for delivery",
    "Delivered",
    "Cancelled"
  ];

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid order ID." });
  }

  if (!allowed.includes(status)) {
    return res.status(400).json({ error: "Invalid order status." });
  }

  const order = db.prepare("SELECT * FROM orders WHERE id = ?").get(id);

  if (!order) return res.status(404).json({ error: "Order not found." });

  const transaction = db.transaction(() => {
    if (status === "Cancelled" && order.status !== "Cancelled" && !order.stock_restored) {
      const items = db.prepare(`
        SELECT product_id, quantity FROM order_items WHERE order_id = ?
      `).all(id);

      const restore = db.prepare(`
        UPDATE products SET stock = stock + ? WHERE id = ?
      `);

      for (const item of items) {
        if (item.product_id) restore.run(item.quantity, item.product_id);
      }

      db.prepare("UPDATE orders SET stock_restored = 1 WHERE id = ?").run(id);
    }

    if (status !== "Cancelled" && order.status === "Cancelled" && order.stock_restored) {
      const items = db.prepare(`
        SELECT product_id, quantity FROM order_items WHERE order_id = ?
      `).all(id);

      for (const item of items) {
        if (!item.product_id) continue;

        const update = db.prepare(`
          UPDATE products SET stock = stock - ?
          WHERE id = ? AND stock >= ?
        `).run(item.quantity, item.product_id, item.quantity);

        if (!update.changes) {
          throw new Error("Not enough stock to reinstate this cancelled order.");
        }
      }

      db.prepare("UPDATE orders SET stock_restored = 0 WHERE id = ?").run(id);
    }

    db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(status, id);
  });

  try {
    transaction();
    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: error.message || "Could not update order." });
  }
});

// Admin products
app.get("/api/admin/products", requireAdmin, (req, res) => {
  res.json(db.prepare(`
    SELECT id, name, category, price, stock,
           prescription_required, image_url
    FROM products ORDER BY id DESC
  `).all());
});

app.post("/api/admin/products", requireAdmin, (req, res) => {
  try {
    const product = validateProductFields(req.body);

    const result = db.prepare(`
      INSERT INTO products
        (name, category, price, stock, prescription_required, image_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      product.name,
      product.category,
      product.price,
      product.stock,
      product.prescriptionRequired,
      product.imageUrl
    );

    res.status(201).json({
      ok: true,
      id: Number(result.lastInsertRowid)
    });
  } catch (error) {
    res.status(400).json({ error: error.message || "Could not create product." });
  }
});

app.patch("/api/admin/products/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid product ID." });
  }

  try {
    const product = validateProductFields(req.body);

    const result = db.prepare(`
      UPDATE products
      SET name = ?, category = ?, price = ?, stock = ?,
          prescription_required = ?, image_url = ?
      WHERE id = ?
    `).run(
      product.name,
      product.category,
      product.price,
      product.stock,
      product.prescriptionRequired,
      product.imageUrl,
      id
    );

    if (!result.changes) {
      return res.status(404).json({ error: "Product not found." });
    }

    res.json({ ok: true });
  } catch (error) {
    res.status(400).json({ error: error.message || "Could not update product." });
  }
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid product ID." });
  }

  const used = db.prepare(`
    SELECT COUNT(*) AS count FROM order_items WHERE product_id = ?
  `).get(id).count;

  if (used) {
    return res.status(409).json({
      error: "This product appears in order history. Set its stock to zero instead of deleting it."
    });
  }

  const result = db.prepare("DELETE FROM products WHERE id = ?").run(id);

  if (!result.changes) {
    return res.status(404).json({ error: "Product not found." });
  }

  res.json({ ok: true });
});

// Static pages
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/track", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use("/assets", express.static(path.join(__dirname, "assets")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API route not found." });
  }
  res.status(404).send("Page not found.");
});

app.listen(PORT, () => {
  console.log(`Kapil Medical server running on port ${PORT}`);
});
