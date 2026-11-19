require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const DB_DIR = path.join(__dirname, "data");
require("fs").mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, "mobet-link.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, balance REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS links (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
 code TEXT UNIQUE NOT NULL, destination TEXT NOT NULL, title TEXT,
 expires_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 clicks INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS visits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, link_id INTEGER NOT NULL,
 visited_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, device TEXT, browser TEXT,
 referrer TEXT, valid INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(link_id) REFERENCES links(id)
);
CREATE TABLE IF NOT EXISTS revenue (
 id INTEGER PRIMARY KEY AUTOINCREMENT, amount REAL NOT NULL,
 note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payouts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
 amount REAL NOT NULL, method TEXT NOT NULL, details TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const defaults = {
 publisher_share_percent: String(process.env.PUBLISHER_SHARE_PERCENT || 60),
 min_payout: String(process.env.MIN_PAYOUT || 10),
 ad_notice: "مساحة إعلانية تجريبية — اربط شبكة إعلانية معتمدة قبل الإطلاق"
};
for (const [k,v] of Object.entries(defaults)) {
 db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);
}

const adminEmail = (process.env.ADMIN_EMAIL || "admin@mobetlink.local").toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeThis-Strong-Password-Now";
if (!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)) {
 const hash = bcrypt.hashSync(adminPassword, 12);
 db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)").run(adminEmail, hash, "admin");
 console.log(`Admin created: ${adminEmail}`);
}
if (process.env.NODE_ENV === "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
 throw new Error("Set SESSION_SECRET to a random value of at least 32 characters in production.");
}

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
 secret: process.env.SESSION_SECRET || "development-only-change-me",
 resave: false, saveUninitialized: false,
 store: new SQLiteStore({ db: "sessions.sqlite", dir: DB_DIR }),
 cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7*24*60*60*1000 }
}));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: true, legacyHeaders: false });
app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);
app.use(express.static(path.join(__dirname, "public")));

const getSetting = (k) => db.prepare("SELECT value FROM settings WHERE key=?").get(k)?.value;
const setSetting = (k,v) => db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k,String(v));
const safeUser = u => ({ id:u.id, email:u.email, role:u.role, balance:Number(u.balance), created_at:u.created_at });
function requireAuth(req,res,next) {
 const u = req.session.user;
 if (!u) return res.status(401).json({ error:"سجّل الدخول أولاً" });
 req.user = db.prepare("SELECT * FROM users WHERE id=?").get(u.id);
 if (!req.user) return res.status(401).json({ error:"الحساب غير موجود" });
 next();
}
function requireAdmin(req,res,next) {
 if (!req.user || req.user.role !== "admin") return res.status(403).json({ error:"غير مصرح لك" });
 next();
}
function validUrl(value) {
 try { const u = new URL(value); return ["http:","https:"].includes(u.protocol); } catch { return false; }
}
function codeGen() { return crypto.randomBytes(5).toString("base64url").slice(0,7); }
function parseAgent(ua="") {
 const s=ua.toLowerCase();
 const device=/mobile|android|iphone/.test(s)?"موبايل":/ipad|tablet/.test(s)?"تابلت":"كمبيوتر";
 const browser=/edg\//.test(s)?"Edge":/firefox\//.test(s)?"Firefox":/chrome\//.test(s)?"Chrome":/safari\//.test(s)?"Safari":"Other";
 return {device,browser};
}

app.post("/api/register", async (req,res) => {
 const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
 if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<8) return res.status(400).json({error:"اكتب بريدًا صحيحًا وكلمة مرور 8 أحرف على الأقل"});
 try {
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(email,password_hash) VALUES(?,?)").run(email,hash);
  req.session.user={id:Number(info.lastInsertRowid)};
  res.json({ok:true});
 } catch { res.status(409).json({error:"البريد الإلكتروني مستخدم بالفعل"}); }
});
app.post("/api/login", async (req,res) => {
 const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:"البريد أو كلمة المرور غير صحيحة"});
 req.session.user={id:u.id}; res.json({ok:true,role:u.role});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",requireAuth,(req,res)=>res.json({user:safeUser(req.user)}));

app.post("/api/links",requireAuth,(req,res)=>{
 const destination=String(req.body.destination||"").trim();
 const title=String(req.body.title||"").trim().slice(0,80);
 const custom=String(req.body.custom||"").trim().toLowerCase();
 const expires=req.body.expires_at ? new Date(req.body.expires_at) : null;
 if (!validUrl(destination)) return res.status(400).json({error:"الرابط الأصلي غير صحيح. استخدم https أو http"});
 if (req.body.expires_at && (!expires || Number.isNaN(expires.getTime()) || expires<=new Date())) return res.status(400).json({error:"تاريخ الانتهاء يجب أن يكون في المستقبل"});
 if (custom && !/^[a-z0-9_-]{3,24}$/.test(custom)) return res.status(400).json({error:"الرابط المخصص من 3 إلى 24 حرفًا إنجليزيًا أو رقمًا"});
 let code=custom||codeGen();
 try {
  db.prepare("INSERT INTO links(user_id,code,destination,title,expires_at) VALUES(?,?,?,?,?)")
   .run(req.user.id,code,destination,title,expires?expires.toISOString():null);
 } catch { return res.status(409).json({error:"هذا الاسم المختصر مستخدم بالفعل"}); }
 res.json({ok:true,link:{code,url:`${BASE_URL}/${code}`,destination,title}});
});
app.get("/api/links",requireAuth,(req,res)=>{
 const rows=db.prepare("SELECT id,code,destination,title,expires_at,created_at,clicks FROM links WHERE user_id=? ORDER BY id DESC").all(req.user.id);
 res.json({links:rows.map(x=>({...x,url:`${BASE_URL}/${x.code}`}))});
});
app.get("/api/stats",requireAuth,(req,res)=>{
 const total=db.prepare("SELECT COUNT(*) n FROM links WHERE user_id=?").get(req.user.id).n;
 const clicks=db.prepare("SELECT COALESCE(SUM(clicks),0) n FROM links WHERE user_id=?").get(req.user.id).n;
 const pending=db.prepare("SELECT COALESCE(SUM(amount),0) n FROM payouts WHERE user_id=? AND status='pending'").get(req.user.id).n;
 const payouts=db.prepare("SELECT id,amount,method,status,created_at FROM payouts WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.user.id);
 res.json({total,clicks,balance:Number(req.user.balance),pending,payouts});
});
app.post("/api/payouts",requireAuth,(req,res)=>{
 const amount=Number(req.body.amount), method=String(req.body.method||"").trim(), details=String(req.body.details||"").trim().slice(0,250);
 const min=Number(getSetting("min_payout")||10);
 if (!Number.isFinite(amount)||amount<min) return res.status(400).json({error:`الحد الأدنى للسحب ${min}`});
 if (!method || details.length<4) return res.status(400).json({error:"اكتب وسيلة السحب وبياناتها"});
 if (amount>Number(req.user.balance)) return res.status(400).json({error:"الرصيد غير كافٍ"});
 const tx=db.transaction(()=>{
  db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount,req.user.id);
  db.prepare("INSERT INTO payouts(user_id,amount,method,details) VALUES(?,?,?,?)").run(req.user.id,amount,method,details);
 });
 tx(); res.json({ok:true});
});
app.get("/api/visits/:code",requireAuth,(req,res)=>{
 const link=db.prepare("SELECT id,user_id FROM links WHERE code=?").get(req.params.code);
 if(!link || (link.user_id!==req.user.id && req.user.role!=="admin")) return res.status(404).json({error:"غير موجود"});
 const visits=db.prepare("SELECT visited_at,device,browser,referrer FROM visits WHERE link_id=? ORDER BY id DESC LIMIT 100").all(link.id);
 res.json({visits});
});

app.get("/api/admin/overview",requireAuth,requireAdmin,(req,res)=>{
 const users=db.prepare("SELECT id,email,role,created_at,balance FROM users ORDER BY id DESC LIMIT 200").all();
 const links=db.prepare("SELECT l.id,l.code,l.title,l.clicks,l.created_at,u.email FROM links l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200").all();
 const payouts=db.prepare("SELECT p.*,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100").all();
 const revenueRows=db.prepare("SELECT * FROM revenue ORDER BY id DESC LIMIT 30").all();
 const revenueTotal=db.prepare("SELECT COALESCE(SUM(amount),0) n FROM revenue").get().n;
 res.json({users,links,payouts,revenueRows,revenueTotal,share:Number(getSetting("publisher_share_percent")),minPayout:Number(getSetting("min_payout"))});
});
app.post("/api/admin/revenue",requireAuth,requireAdmin,(req,res)=>{
 const amount=Number(req.body.amount), note=String(req.body.note||"").slice(0,150);
 if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:"أدخل إيرادًا صحيحًا أكبر من صفر"});
 const share=Number(getSetting("publisher_share_percent"))/100;
 // This is an admin-entered verified net revenue record; it is not inferred from clicks.
 const tx=db.transaction(()=>{
  db.prepare("INSERT INTO revenue(amount,note) VALUES(?,?)").run(amount,note);
  const publisherPool=amount*share;
  const eligible=db.prepare("SELECT id FROM users WHERE role='user'").all();
  if(eligible.length){
   const totalClicks=db.prepare("SELECT COALESCE(SUM(clicks),0) n FROM links").get().n;
   if(totalClicks>0){
    const rows=db.prepare("SELECT user_id,COALESCE(SUM(clicks),0) clicks FROM links GROUP BY user_id").all();
    for(const r of rows) db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(publisherPool*(r.clicks/totalClicks),r.user_id);
   }
  }
 });
 tx(); res.json({ok:true});
});
app.post("/api/admin/settings",requireAuth,requireAdmin,(req,res)=>{
 const share=Number(req.body.share), min=Number(req.body.min_payout);
 if(!Number.isFinite(share)||share<0||share>100||!Number.isFinite(min)||min<0) return res.status(400).json({error:"إعدادات غير صحيحة"});
 setSetting("publisher_share_percent",share); setSetting("min_payout",min); res.json({ok:true});
});
app.post("/api/admin/payout/:id",requireAuth,requireAdmin,(req,res)=>{
 const status=String(req.body.status);
 if(!["paid","rejected"].includes(status)) return res.status(400).json({error:"حالة غير صحيحة"});
 const p=db.prepare("SELECT * FROM payouts WHERE id=?").get(req.params.id);
 if(!p || p.status!=="pending") return res.status(404).json({error:"الطلب غير موجود أو تمت معالجته"});
 const tx=db.transaction(()=>{
  db.prepare("UPDATE payouts SET status=? WHERE id=?").run(status,p.id);
  if(status==="rejected") db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(p.amount,p.user_id);
 });
 tx(); res.json({ok:true});
});
app.post("/api/admin/user/:id/role",requireAuth,requireAdmin,(req,res)=>{
 const role=req.body.role==="admin"?"admin":"user";
 if(Number(req.params.id)===req.user.id && role!=="admin") return res.status(400).json({error:"لا يمكنك إزالة صلاحية الأدمن عن نفسك"});
 db.prepare("UPDATE users SET role=? WHERE id=?").run(role,req.params.id); res.json({ok:true});
});

app.get("/:code",(req,res,next)=>{
 if(["api","admin.html","dashboard.html","index.html","favicon.ico"].includes(req.params.code)) return next();
 const link=db.prepare("SELECT * FROM links WHERE code=?").get(req.params.code);
 if(!link) return res.status(404).sendFile(path.join(__dirname,"public","not-found.html"));
 if(link.expires_at && new Date(link.expires_at)<=new Date()) return res.status(410).sendFile(path.join(__dirname,"public","expired.html"));
 const ua=req.get("user-agent")||"", {device,browser}=parseAgent(ua);
 const ref=(req.get("referer")||"").slice(0,300);
 // Store only coarse device/browser/referrer and time; never store IP or precise location.
 db.prepare("INSERT INTO visits(link_id,device,browser,referrer) VALUES(?,?,?,?)").run(link.id,device,browser,ref||"مباشر");
 db.prepare("UPDATE links SET clicks=clicks+1 WHERE id=?").run(link.id);
 res.send(`<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MOBET LINK</title><link rel="stylesheet" href="/style.css"><body class="interstitial"><main class="adbox"><div class="brand">MOBET <span>LINK</span></div><div class="adlabel">إعلان</div><div class="adplaceholder"><strong>مساحة إعلانية</strong><p>سيظهر الإعلان هنا بعد ربط شبكة إعلانية تسمح بهذا النوع من الصفحات.</p></div><p class="muted">بعد مشاهدة الإعلان، اضغط للمتابعة إلى الرابط المطلوب.</p><a class="btn" href="/go/${encodeURIComponent(link.code)}">متابعة إلى الرابط</a><small class="muted">لا تدخل أي بيانات شخصية في هذه الصفحة.</small></main></body></html>`);
});
app.get("/go/:code",(req,res)=>{
 const link=db.prepare("SELECT destination,expires_at FROM links WHERE code=?").get(req.params.code);
 if(!link) return res.status(404).sendFile(path.join(__dirname,"public","not-found.html"));
 if(link.expires_at && new Date(link.expires_at)<=new Date()) return res.status(410).sendFile(path.join(__dirname,"public","expired.html"));
 res.redirect(302,link.destination);
});

app.listen(PORT,()=>console.log(`MOBET LINK running at ${BASE_URL}`));
