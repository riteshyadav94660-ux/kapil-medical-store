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

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));

app.use(session({
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_BEFORE_DEPLOYMENT",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 28800000
  }
}));

const db = new Database(path.join(__dirname, "kapil-medical.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  prescription_required INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  pincode TEXT NOT NULL DEFAULT '',
  payment_method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  total INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  product_name TEXT NOT NULL,
  unit_price INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  razorpay_payment_id TEXT UNIQUE NOT NULL,
  razorpay_order_id TEXT NOT NULL,
  order_id INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id)
);
`);

const columns = db.prepare("PRAGMA table_info(orders)").all();

if (!columns.some(c => c.name === "pincode")) {
  db.exec("ALTER TABLE orders ADD COLUMN pincode TEXT NOT NULL DEFAULT ''");
}

const razorpay =
  process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET
    ? new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET
      })
    : null;

const username = process.env.ADMIN_USERNAME || "admin";
const password = process.env.ADMIN_PASSWORD || "CHANGE_ME_NOW";

const admin = db.prepare("SELECT id FROM admins LIMIT 1").get();

if (admin) {
  if (process.env.RESET_ADMIN === "true") {
    db.prepare(
      "UPDATE admins SET username=?,password_hash=? WHERE id=?"
    ).run(username, bcrypt.hashSync(password, 12), admin.id);
  }
} else {
  db.prepare(
    "INSERT INTO admins(username,password_hash) VALUES(?,?)"
  ).run(username, bcrypt.hashSync(password, 12));
}

if (!db.prepare("SELECT 1 FROM products LIMIT 1").get()) {
  const ins = db.prepare(
    "INSERT INTO products(name,category,price,stock,prescription_required) VALUES(?,?,?,?,?)"
  );

  [
    ["Paracetamol 500mg", "Medicine", 25, 50, 1],
    ["Vitamin C Tablets", "Medicine", 20, 30, 0],
    ["Antiseptic Cream", "Medicine", 85, 25, 0],
    ["Face Wash", "Cosmetics", 199, 20, 0],
    ["Moisturizing Cream", "Cosmetics", 249, 18, 0],
    ["Sunscreen SPF 50", "Cosmetics", 349, 15, 0]
  ].forEach(x => ins.run(...x));
}

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

const requireAdmin = (req, res, next) =>
  req.session.admin
    ? next()
    : res.status(401).json({ error: "Authentication required" });

const text = (v, max = 500) =>
  typeof v === "string" ? v.trim().slice(0, max) : "";

app.post("/api/login", rateLimit({
  windowMs: 900000,
  max: 10
}), async (req, res) => {
  const a = db.prepare(
    "SELECT * FROM admins WHERE username=?"
  ).get(text(req.body?.username, 100));

  if (!a || !(await bcrypt.compare(
    req.body?.password || "",
    a.password_hash
  ))) {
    return res.status(401).json({
      error: "Invalid credentials"
    });
  }

  req.session.admin = {
    id: a.id,
    username: a.username
  };

  res.json({
    ok: true,
    username: a.username
  });
});

app.post("/api/logout", (req, res) =>
  req.session.destroy(() => res.json({ ok: true }))
);

app.get("/api/me", (req, res) => res.json({
  authenticated: !!req.session.admin,
  username: req.session.admin?.username || null
}));

app.get("/api/products", (req, res) => {
  res.json(
    db.prepare("SELECT * FROM products ORDER BY id DESC").all()
  );
});

const createOrder = db.transaction(data => {
  const quantities = new Map();

  for (const item of data.items) {
    const id = Number(
      item.productId ?? item.product_id ?? item.id
    );

    const qty = Number(item.quantity ?? 1);

    if (
      !Number.isSafeInteger(id) ||
      id < 1 ||
      !Number.isSafeInteger(qty) ||
      qty < 1 ||
      qty > 99
    ) {
      throw Error("Invalid product or quantity");
    }

    quantities.set(id, (quantities.get(id) || 0) + qty);
  }

  if (!quantities.size) {
    throw Error("Your cart is empty");
  }

  let total = 0;
  const lines = [];

  for (const [id, qty] of quantities) {
    const p = db.prepare(
      "SELECT * FROM products WHERE id=?"
    ).get(id);

    if (!p) {
      throw Error("A product in your cart no longer exists");
    }

    if (p.stock < qty) {
      throw Error(`Insufficient stock for ${p.name}`);
    }

    if (p.prescription_required) {
      throw Error(
        `${p.name} requires prescription verification before dispensing`
      );
    }

    total += p.price * qty;
    lines.push({ p, qty });
  }

  if (!Number.isSafeInteger(total) || total <= 0) {
    throw Error("Invalid order total");
  }

  const result = db.prepare(`
    INSERT INTO orders(
      customer_name,phone,address,pincode,
      payment_method,status,total
    )
    VALUES(?,?,?,?,?,?,?)
  `).run(
    data.name,
    data.phone,
    data.address,
    data.pincode,
    data.paymentMethod,
    "Pending",
    total
  );

  const orderId = Number(result.lastInsertRowid);

  const stock = db.prepare(
    "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?"
  );

  const itemInsert = db.prepare(`
    INSERT INTO order_items(
      order_id,product_id,product_name,unit_price,quantity
    )
    VALUES(?,?,?,?,?)
  `);

  for (const { p, qty } of lines) {
    if (stock.run(qty, p.id, qty).changes !== 1) {
      throw Error(`Stock changed for ${p.name}; please retry`);
    }

    itemInsert.run(orderId, p.id, p.name, p.price, qty);
  }

  return { orderId, total };
});

function customerAndItems(body) {
  const c = body.customer || body;

  const name = text(c.name ?? c.customer_name, 100);
  const phone = text(c.phone, 20);
  const address = text(c.address, 500);
  const pincode = text(c.pincode, 10);

  if (
    !name ||
    !/^[6-9]\d{9}$/.test(phone) ||
    !address ||
    !/^\d{6}$/.test(pincode)
  ) {
    throw Error(
      "Valid customer name, mobile, address and 6-digit pincode are required"
    );
  }

  if (!Array.isArray(body.items) || !body.items.length) {
    throw Error("Order items are missing");
  }

  return {
    name,
    phone,
    address,
    pincode,
    items: body.items
  };
}

// CASH ON DELIVERY

app.post("/api/orders", (req, res) => {
  try {
    const b = req.body || {};

    if (String(b.payment_method || "").toUpperCase() !== "COD") {
      return res.status(400).json({
        error: "Select Cash on Delivery or use online checkout"
      });
    }

    const data = customerAndItems(b);
    const result = createOrder({
      ...data,
      paymentMethod: "COD"
    });

    res.status(201).json({
      ok: true,
      id: result.orderId,
      orderId: result.orderId,
      total: result.total,
      status: "Pending",
      message: "COD order placed successfully"
    });
  } catch (e) {
    console.error("COD order error:", e);

    res.status(400).json({
      error: e.message || "Could not place COD order"
    });
  }
});

// CREATE RAZORPAY ORDER

app.post("/api/razorpay/order", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Online payment is not configured"
      });
    }

    const rupees = Number(req.body?.amount);

    if (!Number.isSafeInteger(rupees) || rupees <= 0) {
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
  } catch (e) {
    console.error("Razorpay order error:", e);

    res.status(500).json({
      error: "Unable to create payment order"
    });
  }
});

// VERIFY RAZORPAY PAYMENT

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

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        error: "Missing payment details"
      });
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest();

    const supplied = Buffer.from(
      String(razorpay_signature),
      "hex"
    );

    if (
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) {
      return res.status(400).json({
        error: "Payment verification failed"
      });
    }

    const payment = await razorpay.payments.fetch(
      razorpay_payment_id
    );

    if (
      payment.order_id !== razorpay_order_id ||
      payment.status !== "captured"
    ) {
      return res.status(400).json({
        error: "Payment is not captured"
      });
    }

    const prior = db.prepare(
      "SELECT order_id FROM payments WHERE razorpay_payment_id=?"
    ).get(razorpay_payment_id);

    if (prior) {
      const saved = db.prepare(
        "SELECT id,total FROM orders WHERE id=?"
      ).get(prior.order_id);

      return res.json({
        ok: true,
        verified: true,
        orderId: saved.id,
        total: saved.total,
        message: "Payment and order already recorded"
      });
    }

    const data = customerAndItems(req.body || {});

    const calculated = data.items.reduce((sum, item) => {
      const id = Number(
        item.productId ?? item.product_id ?? item.id
      );

      const qty = Number(item.quantity ?? 1);

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        !Number.isSafeInteger(qty) ||
        qty < 1 ||
        qty > 99
      ) {
        throw Error("Invalid product or quantity");
      }

      const p = db.prepare(
        "SELECT price FROM products WHERE id=?"
      ).get(id);

      if (!p) throw Error("Product not found");

      return sum + p.price * qty;
    }, 0);

    if (payment.amount !== calculated * 100) {
      return res.status(400).json({
        error: "Paid amount does not match current cart total. Contact the store."
      });
    }

    const saved = db.transaction(() => {
      const result = createOrder({
        ...data,
        paymentMethod: "Razorpay"
      });

      db.prepare(`
        INSERT INTO payments(
          razorpay_payment_id,razorpay_order_id,order_id
        )
        VALUES(?,?,?)
      `).run(
        razorpay_payment_id,
        razorpay_order_id,
        result.orderId
      );

      return result;
    })();

    res.json({
      ok: true,
      verified: true,
      orderId: saved.orderId,
      total: saved.total,
      message: "Payment verified and order saved"
    });
  } catch (e) {
    console.error("Razorpay verification/order error:", e);

    res.status(400).json({
      error: e.message ||
        "Payment verification or order saving failed"
    });
  }
});

// ADMIN ORDERS

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const orders = db.prepare(
    "SELECT * FROM orders ORDER BY id DESC"
  ).all();

  const getItems = db.prepare(
    "SELECT * FROM order_items WHERE order_id=?"
  );

  res.json(
    orders.map(o => ({
      ...o,
      items: getItems.all(o.id)
    }))
  );
});

app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  if (![
    "Pending",
    "Confirmed",
    "Shipped",
    "Delivered",
    "Cancelled"
  ].includes(req.body?.status)) {
    return res.status(400).json({
      error: "Invalid status"
    });
  }

  const r = db.prepare(
    "UPDATE orders SET status=? WHERE id=?"
  ).run(req.body.status, req.params.id);

  if (!r.changes) {
    return res.status(404).json({
      error: "Order not found"
    });
  }

  res.json({ ok: true });
});

// ADMIN PRODUCTS

app.get("/api/admin/products", requireAdmin, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM products ORDER BY id DESC").all()
  );
});

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const b = req.body || {};
  const name = text(b.name, 150);
  const category = text(b.category, 80);
  const price = Number(b.price);
  const stock = Number(b.stock);

  if (
    !name ||
    !category ||
    !Number.isSafeInteger(price) ||
    price < 0 ||
    !Number.isSafeInteger(stock) ||
    stock < 0
  ) {
    return res.status(400).json({
      error: "Invalid product"
    });
  }

  const r = db.prepare(`
    INSERT INTO products(
      name,category,price,stock,prescription_required
    )
    VALUES(?,?,?,?,?)
  `).run(
    name,
    category,
    price,
    stock,
    b.prescription_required ? 1 : 0
  );

  res.status(201).json({
    id: Number(r.lastInsertRowid)
  });
});

app.patch("/api/admin/products/:id", requireAdmin, (req, res) => {
  const b = req.body || {};
  const name = text(b.name, 150);
  const category = text(b.category, 80);
  const price = Number(b.price);
  const stock = Number(b.stock);

  if (
    !name ||
    !category ||
    !Number.isSafeInteger(price) ||
    price < 0 ||
    !Number.isSafeInteger(stock) ||
    stock < 0
  ) {
    return res.status(400).json({
      error: "Invalid product"
    });
  }

  const r = db.prepare(`
    UPDATE products
    SET name=?,category=?,price=?,stock=?,prescription_required=?
    WHERE id=?
  `).run(
    name,
    category,
    price,
    stock,
    b.prescription_required ? 1 : 0,
    req.params.id
  );

  if (!r.changes) {
    return res.status(404).json({
      error: "Product not found"
    });
  }

  res.json({ ok: true });
});

app.delete("/api/admin/products/:id", requireAdmin, (req, res) => {
  const r = db.prepare(
    "DELETE FROM products WHERE id=?"
  ).run(req.params.id);

  if (!r.changes) {
    return res.status(404).json({
      error: "Product not found"
    });
  }

  res.json({ ok: true });
});

// WEBSITE ROUTES

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      error: "API endpoint not found"
    });
  }

  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log("Kapil Medical running on port " + PORT);
});
