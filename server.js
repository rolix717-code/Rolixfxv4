require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (process.env.NODE_ENV === 'production') throw new Error('SESSION_SECRET must be set to at least 32 characters in production.');
  process.env.SESSION_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('Using a temporary development session secret. Set SESSION_SECRET in .env.');
}

const db = new Database(path.join(DATA_DIR, 'rolicflix.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS titles (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('movie','tv','anime')),
 year INTEGER, rating TEXT DEFAULT '', overview TEXT DEFAULT '', poster TEXT DEFAULT '', trailer_url TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS watchlist (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title_id INTEGER NOT NULL REFERENCES titles(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,title_id)
);
CREATE TABLE IF NOT EXISTS page_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Safe schema migrations for TMDB-synchronised catalogue entries.
const titleColumns = db.prepare('PRAGMA table_info(titles)').all().map(c => c.name);
if (!titleColumns.includes('tmdb_id')) db.exec('ALTER TABLE titles ADD COLUMN tmdb_id INTEGER');
if (!titleColumns.includes('source')) db.exec("ALTER TABLE titles ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'");
if (!titleColumns.includes('backdrop')) db.exec("ALTER TABLE titles ADD COLUMN backdrop TEXT DEFAULT ''");
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_titles_tmdb_id ON titles(tmdb_id) WHERE tmdb_id IS NOT NULL');
const count = db.prepare('SELECT COUNT(*) AS n FROM titles').get().n;
if (!count) {
 const seed = db.prepare('INSERT INTO titles(title,type,year,rating,overview) VALUES(?,?,?,?,?)');
 [
 ['The Last Tide','movie',2025,'8.7','A cartographer returns to the coast where she grew up, only to find the village slipping into a story she thought she had left behind.'],
 ['Midnight in Tokyo','movie',2024,'8.2','One night, two strangers cross paths in a city that never sleeps.'],
 ['Beyond the Horizon','tv',2025,'9.1','A small crew sets out to uncover the secrets hidden beyond the edge of the known world.'],
 ['Shadow Protocol','movie',2023,'7.9','An analyst discovers a secret operation and must decide who can be trusted.'],
 ['Neon Samurai','anime',2025,'8.9','A young warrior discovers an ancient power in a futuristic city.'],
 ['The Quiet House','movie',2024,'7.8','A family moves into a beautiful old house with a history nobody wants to discuss.'],
 ['Blue Planet Files','tv',2025,'8.5','A documentary team explores the remarkable life hidden beneath the ocean.'],
 ['Skybound Academy','anime',2024,'8.4','Students train to protect their floating city from a mysterious force.']
 ].forEach(x=>seed.run(...x));
}
const adminEmail=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
const adminPassword=process.env.ADMIN_PASSWORD||'';
if (adminEmail && adminPassword) {
 if (adminPassword.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
 const existing=db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail);
 if (!existing) db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(process.env.ADMIN_NAME||'Administrator',adminEmail,bcrypt.hashSync(adminPassword,12),'admin');
 else db.prepare("UPDATE users SET role='admin', status='active' WHERE email=?").run(adminEmail);
} else if (process.env.NODE_ENV === 'production') {
 console.warn('ADMIN_EMAIL / ADMIN_PASSWORD are missing. Set them in the hosting environment to provision an administrator.');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', 'https://image.tmdb.org'], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: null }}}));
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false,limit:'1mb'}));
app.use(session({
 store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR, concurrentDB: true }),
 name: 'rolicflix.sid', secret: process.env.SESSION_SECRET, resave:false, saveUninitialized:false,
 cookie:{ httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV==='production', maxAge:1000*60*60*24*7 }
}));
app.use(express.static(path.join(__dirname,'public'),{ extensions:['html'] }));
app.use('/uploads', express.static(UPLOAD_DIR));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-7',legacyHeaders:false,message:{error:'Too many attempts. Please try again later.'}});
const upload=multer({storage:multer.diskStorage({destination:UPLOAD_DIR,filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())}),limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>{const ok=['image/jpeg','image/png','image/webp','image/avif'].includes(file.mimetype);cb(ok?null:new Error('Only JPG, PNG, WEBP or AVIF image files are allowed.'),ok)}});
const publicUser=u=>({id:u.id,name:u.name,email:u.email,role:u.role,createdAt:u.created_at});
function requireAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Please sign in first.'});const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);if(!u||u.status!=='active'){req.session.destroy(()=>{});return res.status(401).json({error:'Account unavailable. Please contact the administrator.'});}req.user=u;next();}
function requireAdmin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'Administrator access required.'});next();}
function logEvent(event, userId=null){db.prepare('INSERT INTO page_events(event,user_id) VALUES(?,?)').run(event,userId);}
function cleanTitle(t){return {id:t.id,title:t.title,type:t.type,year:t.year,rating:t.rating,overview:t.overview,poster:t.poster,backdrop:t.backdrop||'',source:t.source||'manual',trailerUrl:t.trailer_url,createdAt:t.created_at};}

// TMDB provides catalogue metadata and artwork only; it does not provide movie files or streaming rights.
let lastCatalogSync = null;
let catalogSyncState = { running:false, lastSync:null, added:0, updated:0, error:null };
async function fetchTmdbPage(endpoint, page=1) {
 const token=process.env.TMDB_TOKEN;
 if(!token) throw new Error('TMDB_TOKEN is not configured. Add your TMDB Read Access Token to the server environment.');
 const url=new URL('https://api.themoviedb.org/3/'+endpoint);
 url.searchParams.set('language','en-US'); url.searchParams.set('page',String(page));
 const response=await fetch(url,{headers:{Authorization:`Bearer ${token}`,Accept:'application/json'}});
 if(!response.ok) throw new Error(`TMDB returned HTTP ${response.status}`);
 return response.json();
}
function mapTmdbItem(item, kind) {
 const isTv=kind!=='movie';
 const title=item.title||item.name||item.original_name||item.original_title||'Untitled';
 const date=item.release_date||item.first_air_date||'';
 return {tmdbId:item.id,title,type:kind==='anime'?'anime':(isTv?'tv':'movie'),year:date?Number(date.slice(0,4))||null:null,rating:Number(item.vote_average||0).toFixed(1),overview:String(item.overview||''),poster:item.poster_path?`https://image.tmdb.org/t/p/w500${item.poster_path}`:'',backdrop:item.backdrop_path?`https://image.tmdb.org/t/p/w1280${item.backdrop_path}`:'',source:'tmdb'};
}
async function syncTmdbCatalog() {
 if(catalogSyncState.running) return catalogSyncState;
 catalogSyncState.running=true; catalogSyncState.error=null; let added=0,updated=0;
 try {
  const batches=[
   {endpoint:'trending/movie/week',kind:'movie'},
   {endpoint:'trending/tv/week',kind:'tv'},
   // Japanese-language animation series, used as the anime catalogue.
   {endpoint:'discover/tv?with_genres=16&with_original_language=ja&sort_by=popularity.desc&vote_count.gte=5',kind:'anime'},
   {endpoint:'discover/movie?with_genres=16&with_original_language=ja&sort_by=popularity.desc&vote_count.gte=5',kind:'anime'}
  ];
  const upsert=db.prepare(`INSERT INTO titles(title,type,year,rating,overview,poster,tmdb_id,source,backdrop) VALUES(@title,@type,@year,@rating,@overview,@poster,@tmdbId,@source,@backdrop) ON CONFLICT(tmdb_id) WHERE tmdb_id IS NOT NULL DO UPDATE SET title=excluded.title,type=excluded.type,year=excluded.year,rating=excluded.rating,overview=excluded.overview,poster=excluded.poster,backdrop=excluded.backdrop,source='tmdb'`);
  const exists=db.prepare('SELECT id FROM titles WHERE tmdb_id=?');
  for(const batch of batches){
   // Fetch first two pages per category (up to 40 titles each) per refresh.
   for(let page=1;page<=2;page++){
    const data=await fetchTmdbPage(batch.endpoint,page);
    for(const item of (data.results||[])){
     if(!item.id || !(item.title||item.name)) continue;
     const mapped=mapTmdbItem(item,batch.kind);
     if(exists.get(mapped.tmdbId)) updated++; else added++;
     upsert.run(mapped);
    }
   }
  }
  catalogSyncState={running:false,lastSync:new Date().toISOString(),added,updated,error:null};
 } catch(error) {
  catalogSyncState={...catalogSyncState,running:false,error:error.message};
  console.error('TMDB catalogue sync failed:',error.message);
 }
 return catalogSyncState;
}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'ROLICFLIX'}));
app.get('/api/me',(req,res)=>{if(!req.session.userId)return res.json({user:null});const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);if(!u||u.status!=='active')return res.json({user:null});res.json({user:publicUser(u)});});
app.post('/api/auth/register',authLimiter,async(req,res)=>{
 const name=String(req.body.name||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');
 if(name.length<2||name.length>40)return res.status(400).json({error:'Name must be 2–40 characters.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>190)return res.status(400).json({error:'Enter a valid email address.'});
 if(password.length<10||password.length>128)return res.status(400).json({error:'Password must be at least 10 characters.'});
 if(db.prepare('SELECT id FROM users WHERE email=?').get(email))return res.status(409).json({error:'An account with that email already exists.'});
 try{const hash=await bcrypt.hash(password,12);const result=db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)').run(name,email,hash);req.session.userId=result.lastInsertRowid;logEvent('register',result.lastInsertRowid);res.status(201).json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid))});}catch(e){res.status(500).json({error:'Could not create account.'});}
});
app.post('/api/auth/login',authLimiter,async(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');
 const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!user||user.status!=='active'||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Email or password is incorrect, or this account is disabled.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start session.'});req.session.userId=user.id;logEvent('login',user.id);res.json({user:publicUser(user)});});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(err=>{res.clearCookie('rolicflix.sid');if(err)return res.status(500).json({error:'Could not sign out.'});res.json({ok:true});}));
app.get('/api/titles',(req,res)=>{const rows=db.prepare('SELECT * FROM titles ORDER BY created_at DESC,id DESC').all();res.json({titles:rows.map(cleanTitle)});});
app.get('/api/titles/:id',(req,res)=>{const t=db.prepare('SELECT * FROM titles WHERE id=?').get(Number(req.params.id));if(!t)return res.status(404).json({error:'Title not found.'});res.json({title:cleanTitle(t)});});
app.get('/api/catalogue/status',(req,res)=>res.json({configured:Boolean(process.env.TMDB_TOKEN),...catalogSyncState}));
app.post('/api/admin/catalogue/sync',requireAuth,requireAdmin,async(req,res)=>{const result=await syncTmdbCatalog();if(result.error)return res.status(502).json({error:result.error,...result});res.json(result);});
app.get('/api/watchlist',requireAuth,(req,res)=>{const rows=db.prepare('SELECT t.* FROM titles t JOIN watchlist w ON w.title_id=t.id WHERE w.user_id=? ORDER BY w.created_at DESC').all(req.user.id);res.json({titles:rows.map(cleanTitle)});});
app.post('/api/watchlist/:id',requireAuth,(req,res)=>{const id=Number(req.params.id);if(!db.prepare('SELECT id FROM titles WHERE id=?').get(id))return res.status(404).json({error:'Title not found.'});db.prepare('INSERT OR IGNORE INTO watchlist(user_id,title_id) VALUES(?,?)').run(req.user.id,id);logEvent('watchlist_add',req.user.id);res.json({ok:true});});
app.delete('/api/watchlist/:id',requireAuth,(req,res)=>{db.prepare('DELETE FROM watchlist WHERE user_id=? AND title_id=?').run(req.user.id,Number(req.params.id));res.json({ok:true});});
app.post('/api/events/view', (req,res)=>{logEvent('page_view',req.session.userId||null);res.status(204).end();});

app.get('/api/admin/overview',requireAuth,requireAdmin,(req,res)=>{
 const users=db.prepare('SELECT COUNT(*) n FROM users').get().n;
 const active=db.prepare("SELECT COUNT(*) n FROM users WHERE status='active'").get().n;
 const blocked=db.prepare("SELECT COUNT(*) n FROM users WHERE status='blocked'").get().n;
 const titles=db.prepare('SELECT COUNT(*) n FROM titles').get().n;
 const views=db.prepare("SELECT COUNT(*) n FROM page_events WHERE event='page_view'").get().n;
 const registrations=db.prepare("SELECT COUNT(*) n FROM users WHERE created_at >= datetime('now','-30 days')").get().n;
 const popular=db.prepare(`SELECT t.id,t.title,COUNT(w.user_id) saves FROM titles t LEFT JOIN watchlist w ON w.title_id=t.id GROUP BY t.id ORDER BY saves DESC,t.title LIMIT 5`).all();
 const activity=db.prepare(`SELECT event,COUNT(*) count FROM page_events WHERE created_at >= datetime('now','-7 days') GROUP BY event ORDER BY count DESC`).all();
 res.json({stats:{users,active,blocked,titles,views,registrations},popular,activity});
});
app.get('/api/admin/users',requireAuth,requireAdmin,(req,res)=>{const rows=db.prepare('SELECT id,name,email,role,status,created_at FROM users ORDER BY created_at DESC').all();res.json({users:rows});});
app.patch('/api/admin/users/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),status=req.body.status;
 if(!['active','blocked'].includes(status))return res.status(400).json({error:'Invalid account status.'});
 if(id===req.user.id&&status==='blocked')return res.status(400).json({error:'You cannot block your own administrator account.'});
 const target=db.prepare('SELECT id,role FROM users WHERE id=?').get(id);if(!target)return res.status(404).json({error:'User not found.'});
 if(target.role==='admin')return res.status(400).json({error:'Admin accounts cannot be blocked from this screen.'});
 db.prepare('UPDATE users SET status=? WHERE id=?').run(status,id);res.json({ok:true});
});
app.delete('/api/admin/users/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id);if(id===req.user.id)return res.status(400).json({error:'You cannot delete your own account.'});
 const target=db.prepare('SELECT role FROM users WHERE id=?').get(id);if(!target)return res.status(404).json({error:'User not found.'});if(target.role==='admin')return res.status(400).json({error:'Admin accounts cannot be deleted here.'});
 db.prepare('DELETE FROM users WHERE id=?').run(id);res.json({ok:true});
});
app.post('/api/admin/titles',requireAuth,requireAdmin,(req,res)=>{
 const title=String(req.body.title||'').trim(),type=req.body.type,year=req.body.year?Number(req.body.year):null;
 if(!title||title.length>120||!['movie','tv','anime'].includes(type))return res.status(400).json({error:'Enter a title and valid category.'});
 const r=db.prepare('INSERT INTO titles(title,type,year,rating,overview,poster,trailer_url) VALUES(?,?,?,?,?,?,?)').run(title,type,year,String(req.body.rating||''),String(req.body.overview||'').slice(0,2000),String(req.body.poster||''),String(req.body.trailerUrl||''));
 res.status(201).json({title:cleanTitle(db.prepare('SELECT * FROM titles WHERE id=?').get(r.lastInsertRowid))});
});
app.post('/api/admin/upload-poster',requireAuth,requireAdmin,(req,res,next)=>upload.single('poster')(req,res,err=>{if(err)return res.status(400).json({error:err.message});if(!req.file)return res.status(400).json({error:'Choose an image file.'});res.json({url:'/uploads/'+req.file.filename});}));
app.delete('/api/admin/titles/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id),t=db.prepare('SELECT poster FROM titles WHERE id=?').get(id);if(!t)return res.status(404).json({error:'Title not found.'});
 if(t.poster&&t.poster.startsWith('/uploads/')){const f=path.join(__dirname,'public',t.poster);if(fs.existsSync(f))fs.unlinkSync(f);}
 db.prepare('DELETE FROM titles WHERE id=?').run(id);res.json({ok:true});
});
app.get('/api/admin/export-users.csv',requireAuth,requireAdmin,(req,res)=>{const rows=db.prepare('SELECT id,name,email,role,status,created_at FROM users ORDER BY id').all();const esc=v=>'"'+String(v??'').replace(/"/g,'""')+'"';res.type('text/csv').attachment('rolicflix-users.csv').send(['id,name,email,role,status,created_at',...rows.map(r=>[r.id,r.name,r.email,r.role,r.status,r.created_at].map(esc).join(','))].join('\n'));});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Something went wrong on the server.'});});
app.listen(PORT,()=>{console.log(`ROLICFLIX running on http://localhost:${PORT}`);if(process.env.TMDB_TOKEN){setTimeout(()=>syncTmdbCatalog(),3000);setInterval(()=>syncTmdbCatalog(),12*60*60*1000).unref();}else console.warn('TMDB_TOKEN is not set; automatic catalogue imports are disabled.');});
