const express=require('express'),multer=require('multer'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),cors=require('cors'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DATA=process.env.DATA_DIR||path.join(__dirname,'data'),UP=path.join(DATA,'uploads'),DBF=path.join(DATA,'db.json');
fs.mkdirSync(UP,{recursive:true});
let SECRET=process.env.JWT_SECRET;
if(!SECRET){const f=path.join(DATA,'secret');if(fs.existsSync(f))SECRET=fs.readFileSync(f,'utf8');else{SECRET=crypto.randomBytes(32).toString('hex');fs.writeFileSync(f,SECRET)}}
let db={users:[],videos:[]};try{db=JSON.parse(fs.readFileSync(DBF,'utf8'))}catch(e){}
const save=()=>{fs.writeFileSync(DBF+'.tmp',JSON.stringify(db));fs.renameSync(DBF+'.tmp',DBF)};
const rid=()=>crypto.randomBytes(8).toString('hex');
const FILTERS=['none','bw','sepia','warm','cool','vivid','fade','night'],SCOPES=['pub','phone','link'];
const tokenOf=req=>(req.headers.authorization||'').replace('Bearer ','')||req.query.t||'';
const uidOf=req=>{try{return jwt.verify(tokenOf(req),SECRET).uid}catch(e){return null}};
const need=(req,res,next)=>{const u=uidOf(req);if(!u||!db.users.find(x=>x.id===u))return res.status(401).json({error:'سجّل الدخول من جديد'});req.uid=u;next()};
const sign=u=>({token:jwt.sign({uid:u.id},SECRET,{expiresIn:'60d'}),user:{email:u.email,name:u.name}});
const seen=(v,uid)=>v.scope==='pub'||v.owner===uid;
const view=(v,uid)=>({id:v.id,type:v.type,scope:v.scope,src:v.file?'/uploads/'+v.file:v.url,caption:v.caption,filter:v.filter,ts:v.ts,ownerName:(db.users.find(u=>u.id===v.owner)||{}).name||'مستخدم',mine:v.owner===uid,likesCount:v.likes.length,liked:v.likes.includes(uid)});
const up=multer({storage:multer.diskStorage({destination:UP,filename:(req,f,cb)=>{const m=f.mimetype||'',e=m.includes('webm')?'.webm':m.includes('quicktime')?'.mov':m.includes('mp4')?'.mp4':('.'+(path.extname(f.originalname).slice(1).replace(/[^a-z0-9]/gi,'').slice(0,5)||'mp4'));cb(null,rid()+e)}}),limits:{fileSize:200*1024*1024},fileFilter:(r,f,cb)=>cb(null,(f.mimetype||'').startsWith('video/'))});
const app=express();app.use(cors());app.use(express.json());
app.use('/uploads',express.static(UP,{maxAge:'7d'}));
const mail=/^[^@\s]+@[^@\s]+\.[^@\s]+$/;
app.post('/api/register',(req,res)=>{const e=String(req.body.email||'').trim().toLowerCase(),p=String(req.body.password||'');
 if(!mail.test(e))return res.status(400).json({error:'بريد إلكتروني غير صحيح'});
 if(p.length<6)return res.status(400).json({error:'كلمة المرور قصيرة (6 أحرف على الأقل)'});
 if(db.users.find(u=>u.email===e))return res.status(409).json({error:'هذا البريد مسجّل مسبقاً'});
 const u={id:rid(),email:e,name:e.split('@')[0],hash:bcrypt.hashSync(p,10)};db.users.push(u);save();res.json(sign(u))});
app.post('/api/login',(req,res)=>{const e=String(req.body.email||'').trim().toLowerCase(),u=db.users.find(x=>x.email===e);
 if(!u||!bcrypt.compareSync(String(req.body.password||''),u.hash))return res.status(401).json({error:'البريد أو كلمة المرور غير صحيحة'});res.json(sign(u))});
app.get('/api/me',need,(req,res)=>{const u=db.users.find(x=>x.id===req.uid);res.json({email:u.email,name:u.name})});
app.get('/api/videos',need,(req,res)=>res.json({videos:db.videos.filter(v=>seen(v,req.uid)).sort((a,b)=>b.ts-a.ts).map(v=>view(v,req.uid))}));
app.post('/api/videos',need,(req,res)=>up.single('video')(req,res,err=>{
 if(err)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'الملف كبير (الحد 200MB)':'فشل الرفع'});
 const b=req.body||{},v={id:rid(),owner:req.uid,scope:SCOPES.includes(b.scope)?b.scope:'pub',caption:String(b.caption||'').slice(0,300),filter:FILTERS.includes(b.filter)?b.filter:'none',ts:Date.now(),likes:[]};
 if(req.file){v.type='file';v.file=req.file.filename}
 else if(/^https?:\/\/\S+$/.test(b.url||'')){v.type='url';v.url=b.url}
 else return res.status(400).json({error:'اختر فيديو أو رابطاً صالحاً'});
 db.videos.push(v);save();res.json(view(v,req.uid))}));
const own=(req,res)=>{const v=db.videos.find(x=>x.id===req.params.id);if(!v||v.owner!==req.uid){res.status(404).json({error:'غير موجود'});return null}return v};
app.patch('/api/videos/:id',need,(req,res)=>{const v=own(req,res);if(!v)return;const b=req.body;
 if(SCOPES.includes(b.scope))v.scope=b.scope;if(FILTERS.includes(b.filter))v.filter=b.filter;if(typeof b.caption==='string')v.caption=b.caption.slice(0,300);save();res.json(view(v,req.uid))});
app.delete('/api/videos/:id',need,(req,res)=>{const v=own(req,res);if(!v)return;if(v.file)fs.unlink(path.join(UP,v.file),()=>{});db.videos=db.videos.filter(x=>x!==v);save();res.json({ok:true})});
app.post('/api/videos/:id/like',need,(req,res)=>{const v=db.videos.find(x=>x.id===req.params.id);if(!v||!seen(v,req.uid))return res.status(404).json({error:'غير موجود'});
 const i=v.likes.indexOf(req.uid);i<0?v.likes.push(req.uid):v.likes.splice(i,1);save();res.json({liked:i<0,likesCount:v.likes.length})});
app.get('/api/videos/:id/download',(req,res)=>{const v=db.videos.find(x=>x.id===req.params.id),uid=uidOf(req);
 if(!v||!seen(v,uid))return res.status(404).send('غير موجود');
 if(v.file)return res.download(path.join(UP,v.file),'clip_'+v.id+path.extname(v.file));res.redirect(v.url)});
app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT,'0.0.0.0',()=>console.log('Clips server on :'+PORT));
