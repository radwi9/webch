require('dotenv').config();
const express=require('express'),http=require('http'),path=require('path'),crypto=require('crypto');
const {Server}=require('socket.io'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
const cookieParser=require('cookie-parser'),helmet=require('helmet'),rateLimit=require('express-rate-limit');
const SECRET=process.env.JWT_SECRET||'dev-secret-change-me',PROD=process.env.NODE_ENV==='production';
const db=new Database('chatspace.db');db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE COLLATE NOCASE NOT NULL,email TEXT UNIQUE COLLATE NOCASE NOT NULL,password_hash TEXT NOT NULL,display_name TEXT,avatar TEXT,bio TEXT DEFAULT '',token_version INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,last_seen TEXT);
CREATE TABLE IF NOT EXISTS rooms(id INTEGER PRIMARY KEY,room_uuid TEXT UNIQUE NOT NULL,name TEXT NOT NULL,description TEXT DEFAULT '',avatar TEXT,type TEXT NOT NULL CHECK(type IN('public','private')),owner_id INTEGER NOT NULL REFERENCES users(id),room_code TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS room_members(id INTEGER PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,role TEXT DEFAULT 'member',muted INTEGER DEFAULT 0,joined_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(room_id,user_id));
CREATE TABLE IF NOT EXISTS bans(room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,user_id INTEGER NOT NULL,PRIMARY KEY(room_id,user_id));
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id),message TEXT NOT NULL,reply_to INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT);
CREATE INDEX IF NOT EXISTS idx_msg_room ON messages(room_id,id);
CREATE TABLE IF NOT EXISTS voice_sessions(id INTEGER PRIMARY KEY,room_id INTEGER,user_id INTEGER,joined_at TEXT DEFAULT CURRENT_TIMESTAMP,left_at TEXT);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,text TEXT NOT NULL,is_read INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
const app=express(),server=http.createServer(app),io=new Server(server);
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","'unsafe-inline'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:"],connectSrc:["'self'","ws:","wss:"],mediaSrc:["'self'","blob:"]}}}));
app.use(express.json({limit:'400kb'}));app.use(cookieParser());
app.use('/api',rateLimit({windowMs:60000,limit:300}));
const authLimit=rateLimit({windowMs:15*60000,limit:30});
// CSRF: SameSite=Strict cookie + required custom header on mutating requests
app.use('/api',(q,s,n)=>{if(!['GET','HEAD'].includes(q.method)&&q.get('X-Requested-With')!=='ChatSpace')return s.status(403).json({error:'CSRF check failed.'});n();});
const A=fn=>(q,s,n)=>Promise.resolve(fn(q,s,n)).catch(e=>{console.error(e);s.status(500).json({error:'Server error.'})});
const online=new Map(); // userId -> socket count
const pub=u=>u&&({id:u.id,username:u.username,display_name:u.display_name||u.username,avatar:u.avatar,bio:u.bio,created_at:u.created_at,online:online.has(u.id)});
function userFromToken(t){try{const p=jwt.verify(t,SECRET);const u=db.prepare('SELECT * FROM users WHERE id=?').get(p.id);return u&&u.token_version===p.tv?u:null}catch{return null}}
const auth=(q,s,n)=>{const u=userFromToken(q.cookies.token);if(!u)return s.status(401).json({error:'Not authenticated.'});q.user=u;n();};
const setCookie=(s,u)=>s.cookie('token',jwt.sign({id:u.id,tv:u.token_version},SECRET,{expiresIn:'7d'}),{httpOnly:true,sameSite:'strict',secure:PROD,maxAge:7*864e5});
const rand=n=>{const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';return Array.from(crypto.randomBytes(n),b=>c[b%c.length]).join('')};
const newCode=()=>{let c;do{c=rand(4)+'-'+rand(4)}while(db.prepare('SELECT 1 FROM rooms WHERE room_code=?').get(c));return c};
const clean=(s,max)=>String(s??'').replace(/[\u0000-\u001f]/g,' ').trim().slice(0,max);
const notify=(uid,text)=>{db.prepare('INSERT INTO notifications(user_id,text)VALUES(?,?)').run(uid,text);io.to('u:'+uid).emit('notification',{text});};
// ---- Auth
app.post('/api/auth/register',authLimit,A((q,s)=>{
 const {username,email,password,confirm}=q.body||{};
 if(!/^[A-Za-z0-9_]{3,20}$/.test(username||''))return s.status(400).json({error:'Username must be 3-20 characters: letters, numbers, underscore.'});
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email||''))return s.status(400).json({error:'Invalid email.'});
 if(!password||password.length<8)return s.status(400).json({error:'Password must be at least 8 characters.'});
 if(password!==confirm)return s.status(400).json({error:'Passwords do not match.'});
 if(db.prepare('SELECT 1 FROM users WHERE username=?').get(username))return s.status(409).json({error:'This username is already taken.'});
 if(db.prepare('SELECT 1 FROM users WHERE email=?').get(email))return s.status(409).json({error:'This email is already registered.'});
 const r=db.prepare('INSERT INTO users(username,email,password_hash,display_name)VALUES(?,?,?,?)').run(username,email,bcrypt.hashSync(password,12),username);
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);setCookie(s,u);s.json({user:pub(u)});}));
app.post('/api/auth/login',authLimit,A((q,s)=>{
 const {identifier,password}=q.body||{};
 const u=db.prepare('SELECT * FROM users WHERE username=? OR email=?').get(String(identifier||''),String(identifier||''));
 if(!u||!bcrypt.compareSync(String(password||''),u.password_hash))return s.status(401).json({error:'Invalid credentials.'});
 setCookie(s,u);s.json({user:pub(u)});}));
app.post('/api/auth/logout',auth,A((q,s)=>{db.prepare('UPDATE users SET token_version=token_version+1 WHERE id=?').run(q.user.id);s.clearCookie('token');s.json({ok:true});}));
app.get('/api/auth/me',auth,A((q,s)=>{
 const id=q.user.id;const st={joined:db.prepare('SELECT COUNT(*)c FROM room_members WHERE user_id=?').get(id).c,owned:db.prepare('SELECT COUNT(*)c FROM rooms WHERE owner_id=?').get(id).c,messages:db.prepare('SELECT COUNT(*)c FROM messages WHERE user_id=?').get(id).c,online_users:online.size};
 s.json({user:{...pub(q.user),email:q.user.email},stats:st});}));
// ---- Users
app.get('/api/users',auth,A((q,s)=>{const t='%'+clean(q.query.q,30).replace(/[%_]/g,'')+'%';
 s.json({users:db.prepare('SELECT * FROM users WHERE username LIKE ? OR display_name LIKE ? LIMIT 20').all(t,t).map(pub)});}));
app.get('/api/users/:username',auth,A((q,s)=>{const u=db.prepare('SELECT * FROM users WHERE username=?').get(q.params.username);
 if(!u)return s.status(404).json({error:'User not found.'});
 s.json({user:pub(u),rooms:db.prepare('SELECT COUNT(*)c FROM room_members WHERE user_id=?').get(u.id).c,messages:db.prepare('SELECT COUNT(*)c FROM messages WHERE user_id=?').get(u.id).c});}));
app.patch('/api/users/me',auth,A((q,s)=>{const {display_name,bio,avatar}=q.body||{};
 if(avatar&&(!/^data:image\/(png|jpeg|webp);base64,/.test(avatar)||avatar.length>300000))return s.status(400).json({error:'Avatar must be a PNG/JPEG/WebP under ~200KB.'});
 db.prepare('UPDATE users SET display_name=?,bio=?,avatar=COALESCE(?,avatar),updated_at=CURRENT_TIMESTAMP WHERE id=?').run(clean(display_name,40)||q.user.username,clean(bio,200),avatar||null,q.user.id);
 s.json({user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(q.user.id))});}));
app.post('/api/users/me/password',auth,A((q,s)=>{const {current,password}=q.body||{};
 if(!bcrypt.compareSync(String(current||''),q.user.password_hash))return s.status(400).json({error:'Current password is wrong.'});
 if(!password||password.length<8)return s.status(400).json({error:'Password must be at least 8 characters.'});
 db.prepare('UPDATE users SET password_hash=?,token_version=token_version+1 WHERE id=?').run(bcrypt.hashSync(password,12),q.user.id);
 const u=db.prepare('SELECT * FROM users WHERE id=?').get(q.user.id);setCookie(s,u);s.json({ok:true});}));
app.get('/api/notifications',auth,A((q,s)=>{s.json({notifications:db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30').all(q.user.id)});db.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').run(q.user.id);}));
// ---- Rooms
const roomOnline=id=>db.prepare('SELECT user_id FROM room_members WHERE room_id=?').all(id).filter(m=>online.has(m.user_id)).length;
const roomView=(r,uid)=>{const m=db.prepare('SELECT role FROM room_members WHERE room_id=? AND user_id=?').get(r.id,uid);const o=db.prepare('SELECT username FROM users WHERE id=?').get(r.owner_id);
 const v={id:r.room_uuid,name:r.name,description:r.description,avatar:r.avatar,type:r.type,owner:o&&o.username,created_at:r.created_at,members:db.prepare('SELECT COUNT(*)c FROM room_members WHERE room_id=?').get(r.id).c,online:roomOnline(r.id),is_member:!!m,role:m&&m.role,locked:r.type==='private'&&!m};
 if(r.owner_id===uid)v.room_code=r.room_code;return v;};
const getRoom=id=>db.prepare('SELECT * FROM rooms WHERE room_uuid=?').get(String(id));
const memberOf=(rid,uid)=>db.prepare('SELECT * FROM room_members WHERE room_id=? AND user_id=?').get(rid,uid);
const canManage=(r,uid)=>{const m=memberOf(r.id,uid);return m&&(m.role==='owner'||m.role==='admin')};
function addMember(r,u){db.prepare('INSERT OR IGNORE INTO room_members(room_id,user_id,role)VALUES(?,?,?)').run(r.id,u.id,r.owner_id===u.id?'owner':'member');io.to('room:'+r.room_uuid).emit('members-changed');}
app.get('/api/rooms',auth,A((q,s)=>{const t='%'+clean(q.query.q,40).replace(/[%_]/g,'')+'%';
 s.json({rooms:db.prepare('SELECT * FROM rooms WHERE name LIKE ? ORDER BY id DESC LIMIT 100').all(t).map(r=>roomView(r,q.user.id))});}));
app.post('/api/rooms',auth,A((q,s)=>{const {name,description,type,avatar}=q.body||{};
 if(clean(name,50).length<2)return s.status(400).json({error:'Room name must be at least 2 characters.'});
 if(!['public','private'].includes(type))return s.status(400).json({error:'Invalid room type.'});
 if(avatar&&(!/^data:image\/(png|jpeg|webp);base64,/.test(avatar)||avatar.length>300000))return s.status(400).json({error:'Invalid avatar.'});
 const uuid=rand(6);const r=db.prepare('INSERT INTO rooms(room_uuid,name,description,avatar,type,owner_id,room_code)VALUES(?,?,?,?,?,?,?)').run(uuid,clean(name,50),clean(description,300),avatar||null,type,q.user.id,type==='private'?newCode():null);
 const room=db.prepare('SELECT * FROM rooms WHERE id=?').get(r.lastInsertRowid);addMember(room,q.user);s.json({room:roomView(room,q.user.id)});}));
app.get('/api/rooms/:id',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});s.json({room:roomView(r,q.user.id)});}));
app.patch('/api/rooms/:id',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(r.owner_id!==q.user.id)return s.status(403).json({error:"You don't have permission."});
 const b=q.body||{};const type=['public','private'].includes(b.type)?b.type:r.type;
 db.prepare('UPDATE rooms SET name=?,description=?,avatar=COALESCE(?,avatar),type=?,room_code=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(clean(b.name,50)||r.name,b.description===undefined?r.description:clean(b.description,300),b.avatar&&/^data:image\/(png|jpeg|webp);base64,/.test(b.avatar)&&b.avatar.length<300000?b.avatar:null,type,type==='private'?(r.room_code||newCode()):null,r.id);
 io.to('room:'+r.room_uuid).emit('room-updated');s.json({room:roomView(getRoom(r.room_uuid),q.user.id)});}));
app.post('/api/rooms/:id/regenerate-code',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(r.owner_id!==q.user.id||r.type!=='private')return s.status(403).json({error:"You don't have permission."});
 db.prepare('UPDATE rooms SET room_code=? WHERE id=?').run(newCode(),r.id);s.json({room:roomView(getRoom(r.room_uuid),q.user.id)});}));
app.delete('/api/rooms/:id',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(r.owner_id!==q.user.id)return s.status(403).json({error:"You don't have permission."});
 db.prepare('DELETE FROM rooms WHERE id=?').run(r.id);io.to('room:'+r.room_uuid).emit('room-deleted');s.json({ok:true});}));
const joinLimit=rateLimit({windowMs:60000,limit:10,message:{error:'Too many attempts. Try again later.'}});
app.post('/api/rooms/:id/join',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(db.prepare('SELECT 1 FROM bans WHERE room_id=? AND user_id=?').get(r.id,q.user.id))return s.status(403).json({error:'You are banned from this room.'});
 if(r.type==='private'&&!memberOf(r.id,q.user.id))return s.status(403).json({error:'This room is private. Enter the room code.'});
 addMember(r,q.user);s.json({room:roomView(r,q.user.id)});}));
app.post('/api/rooms/join-private',auth,joinLimit,A((q,s)=>{
 const code=clean(q.body&&q.body.code,20).toUpperCase();const r=db.prepare("SELECT * FROM rooms WHERE type='private' AND room_code=?").get(code);
 if(!r)return s.status(400).json({error:'Invalid room code.'});
 if(q.body.room_id&&q.body.room_id!==r.room_uuid)return s.status(400).json({error:'Invalid room code.'});
 if(db.prepare('SELECT 1 FROM bans WHERE room_id=? AND user_id=?').get(r.id,q.user.id))return s.status(403).json({error:'You are banned from this room.'});
 addMember(r,q.user);s.json({room:roomView(r,q.user.id)});}));
app.post('/api/rooms/:id/join-private',auth,joinLimit,(q,s,n)=>{q.body={...q.body,room_id:q.params.id};q.url='/api/rooms/join-private';app.handle(q,s,n);});
// ---- Messages & members
const msgView=m=>({id:m.id,message:m.message,created_at:m.created_at,reply_to:m.reply_to,user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(m.user_id))});
app.get('/api/rooms/:id/messages',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(!memberOf(r.id,q.user.id))return s.status(403).json({error:"You don't have permission."});
 const before=parseInt(q.query.before)||9e15;
 s.json({messages:db.prepare('SELECT * FROM messages WHERE room_id=? AND id<? ORDER BY id DESC LIMIT 50').all(r.id,before).reverse().map(msgView)});}));
app.post('/api/rooms/:id/messages',auth,rateLimit({windowMs:10000,limit:20,keyGenerator:q=>String(q.user?.id||q.ip),validate:false}),A((q,s)=>{
 const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 const m=memberOf(r.id,q.user.id);if(!m)return s.status(403).json({error:"You don't have permission."});
 if(m.muted)return s.status(403).json({error:'You are muted in this room.'});
 const text=String(q.body.message||'').trim().slice(0,2000);if(!text)return s.status(400).json({error:'Message is empty.'});
 const x=db.prepare('INSERT INTO messages(room_id,user_id,message,reply_to)VALUES(?,?,?,?)').run(r.id,q.user.id,text,parseInt(q.body.reply_to)||null);
 const v=msgView(db.prepare('SELECT * FROM messages WHERE id=?').get(x.lastInsertRowid));io.to('room:'+r.room_uuid).emit('message',v);
 for(const mm of text.matchAll(/@([A-Za-z0-9_]{3,20})/g)){const t=db.prepare('SELECT u.id FROM users u JOIN room_members rm ON rm.user_id=u.id WHERE u.username=? AND rm.room_id=?').get(mm[1],r.id);if(t&&t.id!==q.user.id)notify(t.id,`@${q.user.username} mentioned you in ${r.name}`);}
 s.json({message:v});}));
app.get('/api/rooms/:id/members',auth,A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(!memberOf(r.id,q.user.id))return s.status(403).json({error:"You don't have permission."});
 s.json({members:db.prepare('SELECT u.*,rm.role,rm.muted FROM room_members rm JOIN users u ON u.id=rm.user_id WHERE rm.room_id=?').all(r.id).map(u=>({...pub(u),role:u.role,muted:!!u.muted,voice:voice(r.room_uuid).has(u.id)}))});}));
function moderate(kind){return A((q,s)=>{const r=getRoom(q.params.id);if(!r)return s.status(404).json({error:'Room not found.'});
 if(!canManage(r,q.user.id))return s.status(403).json({error:"You don't have permission."});
 const t=db.prepare('SELECT * FROM users WHERE username=?').get(String(q.body.username||''));const tm=t&&memberOf(r.id,t.id);
 if(!tm)return s.status(404).json({error:'User is not in this room.'});
 if(t.id===r.owner_id||(tm.role==='admin'&&r.owner_id!==q.user.id))return s.status(403).json({error:"You don't have permission."});
 if(kind==='mute')db.prepare('UPDATE room_members SET muted=1-muted WHERE room_id=? AND user_id=?').run(r.id,t.id);
 else{if(kind==='ban')db.prepare('INSERT OR IGNORE INTO bans VALUES(?,?)').run(r.id,t.id);db.prepare('DELETE FROM room_members WHERE room_id=? AND user_id=?').run(r.id,t.id);
  io.to('u:'+t.id).emit('removed',{room:r.room_uuid});notify(t.id,`You were ${kind==='ban'?'banned':'kicked'} from ${r.name}`);kickVoice(r.room_uuid,t.id);}
 io.to('room:'+r.room_uuid).emit('members-changed');s.json({ok:true});});}
app.post('/api/rooms/:id/kick',auth,moderate('kick'));app.post('/api/rooms/:id/ban',auth,moderate('ban'));app.post('/api/rooms/:id/mute',auth,moderate('mute'));
// ---- Socket.IO (presence, typing, WebRTC signaling)
const voiceRooms=new Map(); // roomUuid -> Map(userId -> {sid,muted})
const voice=id=>voiceRooms.get(id)||new Map();
function kickVoice(room,uid){const v=voiceRooms.get(room);if(!v||!v.has(uid))return;const sid=v.get(uid).sid;v.delete(uid);io.to('room:'+room).emit('voice-left',{userId:uid});io.to(sid).emit('voice-kicked');}
io.use((sk,n)=>{const c=(sk.handshake.headers.cookie||'').split(';').map(x=>x.trim().split('=')).find(x=>x[0]==='token');const u=c&&userFromToken(decodeURIComponent(c[1]));if(!u)return n(new Error('unauthorized'));sk.user=u;n();});
io.on('connection',sk=>{const u=sk.user;sk.join('u:'+u.id);online.set(u.id,(online.get(u.id)||0)+1);io.emit('presence',{userId:u.id,online:true});
 const inRoom=r=>{const room=getRoom(r);return room&&memberOf(room.id,u.id)?room:null};
 sk.on('join-room',id=>{const r=inRoom(id);if(r)sk.join('room:'+r.room_uuid);});
 sk.on('leave-room',id=>sk.leave('room:'+id));
 sk.on('typing',id=>{if(sk.rooms.has('room:'+id))sk.to('room:'+id).emit('typing',{room:id,username:u.username});});
 sk.on('voice-join',(id,cb)=>{const r=inRoom(id);if(!r)return cb&&cb({error:"You don't have permission."});
  const v=voiceRooms.get(id)||new Map();voiceRooms.set(id,v);const peers=[...v.entries()].map(([userId,x])=>({userId,sid:x.sid,username:db.prepare('SELECT username FROM users WHERE id=?').get(userId).username,muted:x.muted}));
  v.set(u.id,{sid:sk.id,muted:false});sk.voiceRoom=id;db.prepare('INSERT INTO voice_sessions(room_id,user_id)VALUES(?,?)').run(r.id,u.id);
  sk.to('room:'+id).emit('voice-joined',{userId:u.id,sid:sk.id,username:u.username});cb&&cb({peers});});
 const leave=()=>{const id=sk.voiceRoom;if(!id)return;const v=voiceRooms.get(id);if(v&&v.get(u.id)&&v.get(u.id).sid===sk.id){v.delete(u.id);io.to('room:'+id).emit('voice-left',{userId:u.id});
  const r=getRoom(id);if(r)db.prepare('UPDATE voice_sessions SET left_at=CURRENT_TIMESTAMP WHERE room_id=? AND user_id=? AND left_at IS NULL').run(r.id,u.id);}sk.voiceRoom=null;};
 sk.on('voice-leave',leave);
 sk.on('voice-state',d=>{const v=voiceRooms.get(sk.voiceRoom);if(!v||!v.has(u.id))return;if(typeof d.muted==='boolean')v.get(u.id).muted=d.muted;io.to('room:'+sk.voiceRoom).emit('voice-state',{userId:u.id,muted:!!d.muted,speaking:!!d.speaking});});
 sk.on('signal',({to,data})=>{const v=voiceRooms.get(sk.voiceRoom);if(!v||![...v.values()].some(x=>x.sid===to))return;io.to(to).emit('signal',{from:sk.id,userId:u.id,data});});
 sk.on('disconnect',()=>{leave();const c=(online.get(u.id)||1)-1;if(c<=0){online.delete(u.id);db.prepare('UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=?').run(u.id);io.emit('presence',{userId:u.id,online:false});}else online.set(u.id,c);});});
// ---- Static / SPA fallback
app.use(express.static(path.join(__dirname,'public')));
app.use('/api',(q,s)=>s.status(404).json({error:'Not found.'}));
app.get('*',(q,s)=>s.sendFile(path.join(__dirname,'public','index.html')));
server.listen(process.env.PORT||3000,()=>console.log('ChatSpace running on http://localhost:'+(process.env.PORT||3000)));
