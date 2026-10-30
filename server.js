import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const app = express();
const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !jwtSecret || jwtSecret.length < 32) {
  console.error('DATABASE_URL and a JWT_SECRET of at least 32 characters are required');
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }, max: 5 });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(root, 'public')));

await pool.query(`CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ,
 login_count BIGINT NOT NULL DEFAULT 0, entry_count BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS budgets (
 user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 starting_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
 balance_overrides JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS entries (
 id UUID PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'Other',
 amount NUMERIC(14,2) NOT NULL CHECK (amount > 0), entry_date DATE NOT NULL,
 type TEXT NOT NULL CHECK (type IN ('in','out')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS entries_user_date ON entries(user_id, entry_date DESC);
CREATE TABLE IF NOT EXISTS bug_reports (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
 message TEXT NOT NULL, page TEXT NOT NULL DEFAULT '', app_version TEXT NOT NULL DEFAULT 'v2',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`);

if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
 const email = normalizeEmail(process.env.ADMIN_EMAIL);
 const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
 await pool.query(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin')
 ON CONFLICT(email) DO UPDATE SET role='admin'`, [email, passwordHash]);
}

function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function fail(res, code, error) { return res.status(code).json({ error }); }
function auth(req, res, next) {
 const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
 try { req.user = jwt.verify(token, jwtSecret); next(); } catch { return fail(res, 401, 'Sign in required'); }
}
function admin(req, res, next) { if (req.user.role !== 'admin') return fail(res, 403, 'Admin only'); next(); }
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);

app.get('/api/health', asyncRoute(async (_req,res) => {
 await pool.query('SELECT 1'); res.json({ ok: true, service: 'budget-v2-api' });
}));
app.post('/api/auth/register', asyncRoute(async (req,res) => {
 const email=normalizeEmail(req.body.email), password=String(req.body.password||'');
 if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<10 || password.length>200) return fail(res,400,'Use a valid email and a password of at least 10 characters');
 const passwordHash=await bcrypt.hash(password,12);
 try {
  const {rows}=await pool.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role,created_at',[email,passwordHash]);
  await pool.query('INSERT INTO budgets(user_id) VALUES($1)',[rows[0].id]);
  const user=rows[0], token=jwt.sign({id:user.id,email:user.email,role:user.role},jwtSecret,{expiresIn:'30d'});
  res.status(201).json({token,user:{id:user.id,email:user.email,role:user.role}});
 } catch(e) { if(e.code==='23505') return fail(res,409,'An account with this email already exists'); throw e; }
}));
app.post('/api/auth/login', asyncRoute(async (req,res) => {
 const email=normalizeEmail(req.body.email), password=String(req.body.password||'');
 const {rows}=await pool.query('SELECT id,email,password_hash,role FROM users WHERE email=$1',[email]);
 if(!rows.length || !(await bcrypt.compare(password,rows[0].password_hash))) return fail(res,401,'Email or password is incorrect');
 const u=rows[0]; await pool.query('UPDATE users SET last_seen_at=NOW(),login_count=login_count+1 WHERE id=$1',[u.id]);
 const token=jwt.sign({id:u.id,email:u.email,role:u.role},jwtSecret,{expiresIn:'30d'});
 res.json({token,user:{id:u.id,email:u.email,role:u.role}});
}));
app.get('/api/me',auth,asyncRoute(async(req,res)=>{const {rows}=await pool.query('SELECT id,email,role FROM users WHERE id=$1',[req.user.id]);if(!rows.length)return fail(res,401,'Account no longer exists');res.json({user:rows[0]})}));
app.get('/api/budget',auth,asyncRoute(async(req,res)=>{
 const [{rows:budget}, {rows:entries}]=await Promise.all([
  pool.query('SELECT starting_balance,balance_overrides FROM budgets WHERE user_id=$1',[req.user.id]),
  pool.query('SELECT id,description,category,amount::float AS amount,to_char(entry_date,\'YYYY-MM-DD\') AS date,type,extract(epoch from created_at)*1000 AS "createdAt" FROM entries WHERE user_id=$1 ORDER BY entry_date DESC,created_at DESC',[req.user.id])
 ]);
 if(!budget.length)return fail(res,404,'Budget not initialized');
 res.json({startingBalance:Number(budget[0].starting_balance),balanceOverrides:budget[0].balance_overrides,entries});
}));
app.put('/api/budget/sync',auth,asyncRoute(async(req,res)=>{
 const n=Number(req.body.startingBalance),overrides=Array.isArray(req.body.balanceOverrides)?req.body.balanceOverrides:[],entries=Array.isArray(req.body.entries)?req.body.entries:[];
 if(!Number.isFinite(n)||n<0||overrides.length>200||entries.length>5000)return fail(res,400,'Invalid budget payload');
 if(overrides.some(o=>!/^\d{4}-\d{2}-\d{2}$/.test(o.date)||!Number.isFinite(Number(o.balance))||Number(o.balance)<0))return fail(res,400,'Invalid balance overrides');
 if(entries.some(e=>!/^[\da-f-]{36}$/i.test(String(e.id))||!Number.isFinite(Number(e.amount))||Number(e.amount)<=0||String(e.description||'').length>100||String(e.category||'Other').length>40||!/^\d{4}-\d{2}-\d{2}$/.test(e.date)||!['in','out'].includes(e.type)))return fail(res,400,'Invalid entry');
 const client=await pool.connect();try{await client.query('BEGIN');await client.query('INSERT INTO budgets(user_id,starting_balance,balance_overrides) VALUES($1,$2,$3::jsonb) ON CONFLICT(user_id) DO UPDATE SET starting_balance=EXCLUDED.starting_balance,balance_overrides=EXCLUDED.balance_overrides,updated_at=NOW()',[req.user.id,n,JSON.stringify(overrides)]);await client.query('DELETE FROM entries WHERE user_id=$1',[req.user.id]);for(const e of entries)await client.query('INSERT INTO entries(id,user_id,description,category,amount,entry_date,type,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8/1000.0))',[e.id,req.user.id,String(e.description||''),String(e.category||'Other'),e.amount,e.date,e.type,Number(e.createdAt)||Date.now()]);await client.query('UPDATE users SET entry_count=$2 WHERE id=$1',[req.user.id,entries.length]);await client.query('COMMIT');res.json({ok:true})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}));
app.put('/api/budget',auth,asyncRoute(async(req,res)=>{
 const n=Number(req.body.startingBalance);if(!Number.isFinite(n)||n<0)return fail(res,400,'Invalid starting balance');
 await pool.query('INSERT INTO budgets(user_id,starting_balance) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET starting_balance=EXCLUDED.starting_balance,updated_at=NOW()',[req.user.id,n]);res.json({ok:true});
}));
app.put('/api/budget/balance-overrides',auth,asyncRoute(async(req,res)=>{
 const overrides=Array.isArray(req.body.balanceOverrides)?req.body.balanceOverrides:[];
 if(overrides.length>200||overrides.some(o=>!/^\d{4}-\d{2}-\d{2}$/.test(o.date)||!Number.isFinite(Number(o.balance))||Number(o.balance)<0))return fail(res,400,'Invalid balance overrides');
 await pool.query('UPDATE budgets SET balance_overrides=$2::jsonb,updated_at=NOW() WHERE user_id=$1',[req.user.id,JSON.stringify(overrides)]);res.json({ok:true});
}));
app.post('/api/entries',auth,asyncRoute(async(req,res)=>{
 const {id,description='',category='Other',amount,date,type}=req.body;
 if(!/^[\da-f-]{36}$/i.test(String(id))||!Number.isFinite(Number(amount))||Number(amount)<=0||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!['in','out'].includes(type)||String(description).length>100||String(category).length>40)return fail(res,400,'Invalid entry');
 const {rows}=await pool.query('INSERT INTO entries(id,user_id,description,category,amount,entry_date,type) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[id,req.user.id,String(description),String(category),amount,date,type]);
 await pool.query('UPDATE users SET entry_count=entry_count+1 WHERE id=$1',[req.user.id]);res.status(201).json({id:rows[0].id});
}));
app.put('/api/entries/:id',auth,asyncRoute(async(req,res)=>{
 const {description='',category='Other',amount,date,type}=req.body;
 if(!Number.isFinite(Number(amount))||Number(amount)<=0||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!['in','out'].includes(type)||String(description).length>100||String(category).length>40)return fail(res,400,'Invalid entry');
 const {rowCount}=await pool.query('UPDATE entries SET description=$3,category=$4,amount=$5,entry_date=$6,type=$7 WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id,String(description),String(category),amount,date,type]);if(!rowCount)return fail(res,404,'Entry not found');res.json({ok:true});
}));
app.delete('/api/entries/:id',auth,asyncRoute(async(req,res)=>{const {rowCount}=await pool.query('DELETE FROM entries WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);if(!rowCount)return fail(res,404,'Entry not found');res.json({ok:true})}));
app.delete('/api/budget',auth,asyncRoute(async(req,res)=>{await pool.query('DELETE FROM entries WHERE user_id=$1',[req.user.id]);await pool.query('DELETE FROM budgets WHERE user_id=$1',[req.user.id]);res.json({ok:true})}));
app.post('/api/bug-reports',auth,asyncRoute(async(req,res)=>{
 const message=String(req.body.message||'').trim();if(message.length<5||message.length>4000)return fail(res,400,'Report must be 5 to 4000 characters');
 const {rows}=await pool.query('INSERT INTO bug_reports(user_id,message,page,app_version) VALUES($1,$2,$3,$4) RETURNING id,created_at',[req.user.id,message,String(req.body.page||'').slice(0,300),String(req.body.appVersion||'v2').slice(0,30)]);
 res.status(201).json({ok:true,id:rows[0].id,createdAt:rows[0].created_at});
}));
app.get('/api/admin/overview',auth,admin,asyncRoute(async(_req,res)=>{
 const [{rows:counts},{rows:users},{rows:reports}]=await Promise.all([
  pool.query(`SELECT (SELECT count(*) FROM users)::int AS users,(SELECT count(*) FROM entries)::int AS entries,(SELECT count(*) FROM bug_reports)::int AS reports,(SELECT count(*) FROM users WHERE created_at>=date_trunc('day',NOW()))::int AS signups_today,(SELECT count(*) FROM users WHERE last_seen_at>=NOW()-INTERVAL '7 days')::int AS active_7d`),
  pool.query('SELECT id,email,role,created_at,last_seen_at,login_count,entry_count FROM users ORDER BY created_at DESC LIMIT 500'),
  pool.query('SELECT b.id,b.message,b.page,b.app_version,b.created_at,u.email FROM bug_reports b LEFT JOIN users u ON u.id=b.user_id ORDER BY b.created_at DESC LIMIT 200')
 ]);res.json({stats:counts[0],users,reports});
}));
app.post('/api/admin/users/:id/role',auth,admin,asyncRoute(async(req,res)=>{if(!['user','admin'].includes(req.body.role))return fail(res,400,'Invalid role');const {rowCount}=await pool.query('UPDATE users SET role=$2 WHERE id=$1',[req.params.id,req.body.role]);if(!rowCount)return fail(res,404,'User not found');res.json({ok:true})}));
app.get('/admin.html',(_req,res)=>res.sendFile(path.join(root,'public','admin.html')));
app.use((err,_req,res,_next)=>{console.error('request failed',err.message);res.status(500).json({error:'Internal server error'});});
app.listen(port,'0.0.0.0',()=>console.log(`budget-v2 listening on ${port}`));
process.on('SIGTERM',async()=>{await pool.end();process.exit(0)});
