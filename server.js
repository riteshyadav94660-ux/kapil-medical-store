import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "path";
import {fileURLToPath} from "url";
const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express(), db=new Database(path.join(__dirname,"kapil-medical.db"));
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:"1mb"}));
app.use(express.static(path.join(__dirname,"..")));
app.use(session({
 secret:process.env.SESSION_SECRET||"CHANGE_THIS_BEFORE_DEPLOYMENT",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:1000*60*60*8}
}));
db.exec(`CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT NOT NULL,price INTEGER NOT NULL,stock INTEGER NOT NULL DEFAULT 0,prescription_required INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,customer_name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,pincode TEXT NOT NULL,payment_method TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Pending',total INTEGER NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
if(!db.prepare("SELECT 1 FROM admins LIMIT 1").get()){
 const username=process.env.ADMIN_USERNAME||"admin";
 const password=process.env.ADMIN_PASSWORD||"CHANGE_ME_NOW";
 db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)").run(username,bcrypt.hashSync(password,12));
 console.log("Admin initialized. Set ADMIN_USERNAME, ADMIN_PASSWORD and SESSION_SECRET before deployment.");
}
if(!db.prepare("SELECT 1 FROM products LIMIT 1").get()){
 const i=db.prepare("INSERT INTO products(name,category,price,stock,prescription_required) VALUES(?,?,?,?,?)");
 [["Paracetamol 500mg","Medicine",25,50,1],["Vitamin C Tablets","Medicine",120,30,0],["Antiseptic Cream","Medicine",85,25,0],["Face Wash","Cosmetics",199,20,0],["Moisturizing Cream","Cosmetics",249,18,0],["Sunscreen SPF 50","Cosmetics",349,15,0]].forEach(x=>i.run(...x));
}
const api=rateLimit({windowMs:15*60*1000,max:200}); app.use("/api",api);
const requireAdmin=(req,res,next)=>req.session.admin?next():res.status(401).json({error:"Authentication required"});
app.post("/api/login",rateLimit({windowMs:15*60*1000,max:10}),async(req,res)=>{
 const a=db.prepare("SELECT * FROM admins WHERE username=?").get(req.body.username||"");
 if(!a||!(await bcrypt.compare(req.body.password||"",a.password_hash))) return res.status(401).json({error:"Invalid credentials"});
 req.session.admin={id:a.id,username:a.username};res.json({ok:true,username:a.username});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({authenticated:!!req.session.admin,username:req.session.admin?.username||null}));
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/orders",(req,res)=>{
 const {customer_name,phone,address,pincode,payment_method,total}=req.body;
 if(!customer_name||!phone||!address||!pincode||!payment_method||!Number.isFinite(total)) return res.status(400).json({error:"Incomplete order"});
 const r=db.prepare("INSERT INTO orders(customer_name,phone,address,pincode,payment_method,total) VALUES(?,?,?,?,?,?)").run(customer_name,phone,address,pincode,payment_method,total);
 res.status(201).json({id:r.lastInsertRowid,status:"Pending"});
});
app.get("/api/admin/orders",requireAdmin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all()));
app.patch("/api/admin/orders/:id",requireAdmin,(req,res)=>{
 const ok=["Pending","Confirmed","Shipped","Delivered","Cancelled"]; if(!ok.includes(req.body.status))return res.status(400).json({error:"Invalid status"});
 db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);res.json({ok:true});
});
app.get("/api/admin/products",requireAdmin,(req,res)=>res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all()));
app.post("/api/admin/products",requireAdmin,(req,res)=>{
 const {name,category,price,stock,prescription_required}=req.body;if(!name||!category||!Number.isFinite(price)||!Number.isInteger(stock))return res.status(400).json({error:"Invalid product"});
 const r=db.prepare("INSERT INTO products(name,category,price,stock,prescription_required) VALUES(?,?,?,?,?)").run(name,category,price,stock,prescription_required?1:0);res.status(201).json({id:r.lastInsertRowid});
});
app.patch("/api/admin/products/:id",requireAdmin,(req,res)=>{
 const {name,category,price,stock,prescription_required}=req.body;
 db.prepare("UPDATE products SET name=?,category=?,price=?,stock=?,prescription_required=? WHERE id=?").run(name,category,price,stock,prescription_required?1:0,req.params.id);res.json({ok:true});
});
app.delete("/api/admin/products/:id",requireAdmin,(req,res)=>{db.prepare("DELETE FROM products WHERE id=?").run(req.params.id);res.json({ok:true})});
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"admin.html")));
app.use((req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Kapil Medical running on port "+(process.env.PORT||3000)));
