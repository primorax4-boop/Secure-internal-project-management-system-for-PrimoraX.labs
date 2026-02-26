'use strict';

// ══════════════════════════════════════════════════════════
//  PrimoraX.labs — app.js
//  ALL data lives in Firebase Realtime Database.
//  No local-only static lists. Everything is live.
//  IndexedDB is used ONLY for uploaded file blobs.
// ══════════════════════════════════════════════════════════

// ── FIREBASE CONFIG ──────────────────────────────────────
const FIREBASE_CONFIG = {
  apiKey:            'AIzaSyC8SaNwndgJNNcu9IMAzlwZFuP6yMIR7NA',
  authDomain:        'primorax-ops.firebaseapp.com',
  databaseURL:       'https://primorax-ops-default-rtdb.firebaseio.com',
  projectId:         'primorax-ops',
  storageBucket:     'primorax-ops.firebasestorage.app',
  messagingSenderId: '525693856762',
  appId:             '1:525693856762:web:0606cc21534b0a75a69243'
};

// Firebase DB paths
const FB = {
  users:       'users',
  projects:    'projects',
  tasks:       'tasks',
  docs:        'docs',
  comments:    'comments',
  archNotes:   'archNotes',
  chat:        'groupChat',
  presence:    'presence',
};

let db = null;

// ── SECURITY ─────────────────────────────────────────────
const SEC = {
  TOKEN_KEY:       'px_session_token',
  TOKEN_HASH_KEY:  'px_session_hash',
  TOKEN_USER_KEY:  'px_session_user',
  TOKEN_EXPIRY_KEY:'px_session_expiry',
  REMEMBER_KEY:    'px_remember',
  FAIL_KEY:        'px_fail_',
  LOCK_KEY:        'px_lock_',
  MAX_FAILS:       5,
  LOCK_SECS:       30,
  SESSION_SECS:    1800,
  REMEMBER_DAYS:   7,
};

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function genToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function getFailCount(un) { return parseInt(localStorage.getItem(SEC.FAIL_KEY+un)||'0'); }
function incFail(un) {
  const n = getFailCount(un)+1;
  localStorage.setItem(SEC.FAIL_KEY+un, n);
  if (n >= SEC.MAX_FAILS) localStorage.setItem(SEC.LOCK_KEY+un, Date.now()+SEC.LOCK_SECS*1000);
  return n;
}
function clearFail(un) { localStorage.removeItem(SEC.FAIL_KEY+un); localStorage.removeItem(SEC.LOCK_KEY+un); }
function getLockRemain(un) { const u=parseInt(localStorage.getItem(SEC.LOCK_KEY+un)||'0'); const r=Math.ceil((u-Date.now())/1000); return r>0?r:0; }

async function createSession(username, remember) {
  const token = genToken();
  const hash  = await sha256hex(token+username+navigator.userAgent.slice(0,30));
  const store = remember ? localStorage : sessionStorage;
  const expiry = remember ? Date.now()+SEC.REMEMBER_DAYS*86400*1000 : Date.now()+SEC.SESSION_SECS*1000;
  clearSession();
  store.setItem(SEC.TOKEN_KEY, token);
  store.setItem(SEC.TOKEN_HASH_KEY, hash);
  store.setItem(SEC.TOKEN_USER_KEY, username);
  store.setItem(SEC.TOKEN_EXPIRY_KEY, expiry);
  if (remember) localStorage.setItem(SEC.REMEMBER_KEY,'1');
}
async function validateSession() {
  for (const store of [sessionStorage,localStorage]) {
    const token=store.getItem(SEC.TOKEN_KEY), hash=store.getItem(SEC.TOKEN_HASH_KEY),
          user=store.getItem(SEC.TOKEN_USER_KEY), expiry=parseInt(store.getItem(SEC.TOKEN_EXPIRY_KEY)||'0');
    if (!token||!hash||!user||!expiry) continue;
    if (Date.now()>expiry) { store.removeItem(SEC.TOKEN_KEY); continue; }
    const expected=await sha256hex(token+user+navigator.userAgent.slice(0,30));
    if (expected!==hash) { clearSession(); return null; }
    if (store===sessionStorage) store.setItem(SEC.TOKEN_EXPIRY_KEY, Date.now()+SEC.SESSION_SECS*1000);
    return user;
  }
  return null;
}
function clearSession() {
  [sessionStorage,localStorage].forEach(s=>{
    s.removeItem(SEC.TOKEN_KEY); s.removeItem(SEC.TOKEN_HASH_KEY);
    s.removeItem(SEC.TOKEN_USER_KEY); s.removeItem(SEC.TOKEN_EXPIRY_KEY);
  });
  localStorage.removeItem(SEC.REMEMBER_KEY);
}

let _inactivityTimer=null;
function resetInactivity() {
  if (_rememberMe) return;
  clearTimeout(_inactivityTimer);
  _inactivityTimer=setTimeout(()=>{ notify('Session expired','err'); setTimeout(doLogout,1500); },SEC.SESSION_SECS*1000);
}
function startInactivityWatch() {
  ['click','keydown','touchstart','scroll'].forEach(e=>document.addEventListener(e,resetInactivity,{passive:true}));
  resetInactivity();
}
function stopInactivityWatch() { clearTimeout(_inactivityTimer); }

// ── INDEXEDDB (file blobs only) ──────────────────────────
let IDB = null;
async function openIDB() {
  return new Promise((res,rej)=>{
    const req = indexedDB.open('PrimoraXFiles',1);
    req.onupgradeneeded = e => { const db=e.target.result; if(!db.objectStoreNames.contains('files')) db.createObjectStore('files',{keyPath:'id'}); };
    req.onsuccess = e=>{ IDB=e.target.result; res(IDB); };
    req.onerror = ()=>rej(req.error);
  });
}
function saveFile(id,data){ return new Promise((res,rej)=>{ if(!IDB){res();return;} const tx=IDB.transaction('files','readwrite'); tx.objectStore('files').put({id,...data}); tx.oncomplete=res; tx.onerror=()=>rej(tx.error); }); }
function getFile(id){ return new Promise(res=>{ if(!IDB){res(null);return;} const tx=IDB.transaction('files','readonly'); const req=tx.objectStore('files').get(id); req.onsuccess=()=>res(req.result||null); req.onerror=()=>res(null); }); }
function deleteFile(id){ return new Promise(res=>{ if(!IDB){res();return;} const tx=IDB.transaction('files','readwrite'); tx.objectStore('files').delete(id); tx.oncomplete=res; tx.onerror=res; }); }

// ── STATE ────────────────────────────────────────────────
let CU = null;
let _rememberMe = false;
let page = 'dashboard';
let selProj = null;
let activeTab = 'overview';
let taskExp = {};
let docOpen = {};
let fStatus = 'All';
let fVis = 'all';
let fTask = 'All';
let selMembers = [];
let uploadedFile = null;
let typingUsers = {};
let typingTimeout = null;

// Live data from Firebase
let USERS = {};
let projects = [];
let tasks = [];
let docs = [];
let archNotes = [];
let projComments = {};
let groupChat = [];

// Firebase listeners (to detach on logout)
let _listeners = {};

// ── CONSTANTS ────────────────────────────────────────────
const SC = {Created:'#4fc3f7',Approved:'#56c26a','In Development':'#fcb144',Review:'#cc88e8',Delivered:'#6ee7b7',Archived:'#7a9ab0','In Progress':'#fcb144',Completed:'#6ee7b7','Not Started':'#6b8fae'};
const VC = {'ceo-only':{l:'CEO Only',c:'#f04545',i:'👑'},'team-only':{l:'Team Only',c:'#42a5f5',i:'👥'},shared:{l:'Shared',c:'#56c26a',i:'🌐'}};
const FI = {pdf:'📄',xlsx:'📊',docx:'📝',zip:'📦',png:'🖼',jpg:'🖼',jpeg:'🖼',gif:'🖼',mp4:'🎬',mp3:'🎵',dwg:'📐',txt:'📋',ppt:'📊',pptx:'📊'};
const QUOTES = {
  CEO:['Full control. Full visibility. Let\'s build something great today.'],
  Electronics:['Great circuits start with great thinking. Ready to design?'],
  Mechanical:['Engineering is the art of making what you want happen.'],
  Analysis:['Data tells the story. You write it.'],
  Research:['Knowledge is the foundation of every great project.'],
  Media:['Presentation is everything. Make it shine.'],
  Management:['Direction and purpose in every decision.'],
  'Electronics Assembly & Testing':['Precision in assembly is everything. Let\'s test it right.'],
};

// ── DEFAULT SEED USERS (written once to Firebase) ────────
const SEED_USERS = {
  'sumukh.ceo'       : {password:'PrimoraX@CEO2025',    name:'Sumukh Bharadwaj K S', role:'CEO',  domain:'Management',                       avatar:'SB', color:'#7b1fa2', enabled:true},
  'vishal.elec'      : {password:'elec@vishal01',        name:'Vishal Rajoor',         role:'team', domain:'Electronics',                     avatar:'VR', color:'#1565c0', enabled:true},
  'yashas.mech'      : {password:'mech@yashas01',        name:'Yashas Raj',            role:'team', domain:'Mechanical',                      avatar:'YR', color:'#00695c', enabled:true},
  'vaishak.analysis' : {password:'analysis@vaishak01',   name:'Vaishakh Shetty B',     role:'team', domain:'Analysis',                       avatar:'VS', color:'#1976d2', enabled:true},
  'subbaiah.research': {password:'research@subbaiah01',  name:'Thaman Subbaiah',       role:'team', domain:'Research',                       avatar:'TS', color:'#6a1b9a', enabled:true},
  'thilak.media'     : {password:'media@thilak01',       name:'Thilak',                role:'team', domain:'Media',                          avatar:'TM', color:'#c2185b', enabled:true},
  'bindushree.coord' : {password:'coord@bindushree01',   name:'Bindushree H M',        role:'team', domain:'Research',                       avatar:'BH', color:'#6a1b9a', enabled:true},
  'manoj.elec'       : {password:'elec@manoj01',         name:'Manoj Y S',             role:'team', domain:'Electronics Assembly & Testing',  avatar:'MY', color:'#e65100', enabled:true},
};

// ── UTILS ────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const isCEO = () => CU?.role === 'CEO';
const myProj = () => isCEO() ? projects : projects.filter(p => (p.assignedMembers||[]).includes(CU.username));
const myTasks = () => isCEO() ? tasks : tasks.filter(t => t.assignedTo === CU.username);
function canSee(d) {
  if (isCEO()) return true;
  if (d.visibility==='ceo-only') return false;
  if (d.visibility==='team-only') return d.uploadedBy===CU.username;
  if (d.visibility==='shared') { const p=projects.find(x=>x.id===d.projectId); return (p?.assignedMembers||[]).includes(CU.username); }
  return false;
}
function fi(t){return FI[t?.toLowerCase()]||'📎';}
function fmtD(d){if(!d)return'—';return new Date(d).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'});}
function fmtDT(d){return new Date(d).toLocaleDateString('en-IN',{weekday:'long',day:'2-digit',month:'long',year:'numeric'});}
function fmtSize(bytes){if(!bytes)return'—';if(bytes<1024)return bytes+' B';if(bytes<1048576)return(bytes/1024).toFixed(1)+' KB';return(bytes/1048576).toFixed(1)+' MB';}
function bdg(label,color,sm){const p=sm?'2px 7px':'3px 10px',fs=sm?'10px':'11px';return`<span class="badge" style="background:${color}1f;color:${color};border:1px solid ${color}40;padding:${p};font-size:${fs};">${label}</span>`;}
function av(init,sz=36,col='#0d47a1'){return`<div class="avatar" style="width:${sz}px;height:${sz}px;background:${col};font-size:${Math.round(sz*.36)}px;color:#fff;">${init}</div>`;}
function pb(val,col='#1976d2'){return`<div class="pbar-wrap"><div class="pbar" style="width:${Math.min(100,val||0)}%;background:${col};"></div></div>`;}
function gid(p){return p+'-'+Date.now().toString(36).toUpperCase();}
function greetWord(){const h=new Date().getHours();if(h<12)return'Good morning';if(h<17)return'Good afternoon';return'Good evening';}
function notify(msg,type='ok'){const n=$('notif');n.textContent=(type==='err'?'⚠ ':'✓ ')+msg;n.className=type==='err'?'err':'';n.style.display='block';clearTimeout(n._t);n._t=setTimeout(()=>n.style.display='none',3200);}
function toggleSB(){$('sidebar').classList.toggle('open');$('sb-overlay').classList.toggle('on');}
function closeSB(){$('sidebar').classList.remove('open');$('sb-overlay').classList.remove('on');}
function escapeHtml(str){return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/\n/g,'<br>');}
function showLoading(msg='Loading…'){
  const el=document.createElement('div');el.id='loading-overlay';el.className='loading-overlay';
  el.innerHTML=`<div class="spinner"></div><p>${msg}</p>`;
  document.body.appendChild(el);
}
function hideLoading(){const el=$('loading-overlay');if(el)el.remove();}

// ── FIREBASE INIT ────────────────────────────────────────
function initFirebase() {
  if (!firebase.apps.length) firebase.initializeApp(FIREBASE_CONFIG);
  db = firebase.database();
}

// ── FIREBASE: seed users if not exist ───────────────────
async function ensureUsersSeeded() {
  const snap = await db.ref(FB.users).once('value');
  if (!snap.exists()) {
    // First run: write seed users
    await db.ref(FB.users).set(SEED_USERS);
    USERS = { ...SEED_USERS };
  } else {
    USERS = snap.val() || {};
  }
}

// ── FIREBASE: live listeners ──────────────────────────────
function attachListeners() {
  // USERS
  _listeners.users = db.ref(FB.users).on('value', snap => {
    USERS = snap.val() || {};
    if (page === 'users') renderContent();
  });

  // PROJECTS
  _listeners.projects = db.ref(FB.projects).on('value', snap => {
    const raw = snap.val() || {};
    projects = Object.values(raw);
    if (selProj) {
      const updated = projects.find(p=>p.id===selProj.id);
      if (updated) selProj = updated;
    }
    if (['dashboard','projects','proj-detail','finance','delivery'].includes(page)) renderContent();
  });

  // TASKS
  _listeners.tasks = db.ref(FB.tasks).on('value', snap => {
    const raw = snap.val() || {};
    tasks = Object.values(raw);
    if (['dashboard','tasks','proj-detail'].includes(page)) renderContent();
  });

  // DOCS
  _listeners.docs = db.ref(FB.docs).on('value', snap => {
    const raw = snap.val() || {};
    docs = Object.values(raw);
    if (['documents','proj-detail'].includes(page)) renderContent();
  });

  // ARCH NOTES
  _listeners.archNotes = db.ref(FB.archNotes).on('value', snap => {
    const raw = snap.val() || {};
    archNotes = Object.values(raw).sort((a,b)=>a.order-b.order||0);
    if (page === 'architecture') renderContent();
  });

  // PROJECT COMMENTS
  _listeners.comments = db.ref(FB.comments).on('value', snap => {
    projComments = snap.val() || {};
    if (page === 'proj-detail' && activeTab === 'comments') renderContent();
  });

  // GROUP CHAT
  _listeners.chat = db.ref(FB.chat).limitToLast(200).on('value', snap => {
    const raw = snap.val() || {};
    groupChat = Object.entries(raw).map(([k,v])=>({id:k,...v})).sort((a,b)=>(a.ts||0)-(b.ts||0));
    if (page === 'groupchat') {
      const msgArea = $('chat-messages');
      if (msgArea) {
        const atBottom = msgArea.scrollHeight - msgArea.scrollTop - msgArea.clientHeight < 80;
        msgArea.innerHTML = buildChatMessages();
        if (atBottom) setTimeout(()=>{msgArea.scrollTop=msgArea.scrollHeight;},50);
      }
    }
  });

  // PRESENCE (typing indicators)
  _listeners.presence = db.ref(FB.presence).on('value', snap => {
    const presences = snap.val() || {};
    typingUsers = {};
    Object.entries(presences).forEach(([u,p])=>{
      if (u!==CU.username && p && p.typing && p.lastSeen>(Date.now()-4000)) {
        typingUsers[u] = p.lastSeen;
      }
    });
    if (page==='groupchat') {
      const msgArea=$('chat-messages');
      if (msgArea) { msgArea.innerHTML=buildChatMessages(); }
    }
  });
}

function detachListeners() {
  try {
    if (db) {
      db.ref(FB.users).off();
      db.ref(FB.projects).off();
      db.ref(FB.tasks).off();
      db.ref(FB.docs).off();
      db.ref(FB.archNotes).off();
      db.ref(FB.comments).off();
      db.ref(FB.chat).off();
      db.ref(FB.presence).off();
    }
  } catch(e){}
  _listeners = {};
}

// ── AUTH LOGIC ───────────────────────────────────────────
let _rmOn = false;

function toggleRM() {
  _rmOn = !_rmOn;
  const tog=$('rm-toggle'), knob=$('rm-knob'), lbl=$('rm-on');
  if (_rmOn) { tog.style.background='rgba(26,114,212,.35)';tog.style.borderColor='var(--blue2)';knob.style.left='17px';knob.style.background='var(--blue3)';if(lbl)lbl.style.display='inline'; }
  else { tog.style.background='var(--bg5)';tog.style.borderColor='var(--border2)';knob.style.left='1px';knob.style.background='var(--text5)';if(lbl)lbl.style.display='none'; }
}

function togglePW() {
  const p=$('l-pass'),e=$('l-eye');
  p.type=p.type==='password'?'text':'password';
  e.textContent=p.type==='password'?'👁':'🙈';
}

async function doLogin() {
  const un = $('l-user').value.trim().toLowerCase();
  const pw = $('l-pass').value;
  const errEl=$('l-err'), lockEl=$('l-lock');

  const lockRemain=getLockRemain(un);
  if (lockRemain>0) {
    lockEl.style.display='block';
    lockEl.textContent=`⏱ Too many attempts. Try again in ${lockRemain}s.`;
    const ticker=setInterval(()=>{
      const r=getLockRemain(un);
      if(r<=0){clearInterval(ticker);lockEl.style.display='none';}
      else lockEl.textContent=`⏱ Too many attempts. Try again in ${r}s.`;
    },1000);
    return;
  }

  // Fetch fresh user data from Firebase
  showLoading('Verifying…');
  try {
    const snap = await db.ref(`${FB.users}/${un}`).once('value');
    hideLoading();
    const u = snap.val();
    if (u && u.password===pw && u.enabled!==false) {
      clearFail(un);
      CU = { username: un, ...u };
      _rememberMe = _rmOn;
      await createSession(un, _rmOn);
      showScreen('s-welcome');
      buildWelcome();
      attachListeners();
      startPresence();
    } else {
      const fails=incFail(un);
      const remaining=SEC.MAX_FAILS-fails;
      errEl.style.display='block';
      errEl.textContent=remaining>0?`⚠ Invalid credentials. ${remaining} attempt${remaining!==1?'s':''} left.`:`⛔ Account locked for ${SEC.LOCK_SECS}s.`;
      setTimeout(()=>errEl.style.display='none',4000);
      const card=document.querySelector('.login-card');
      card.style.animation='none';card.offsetHeight;card.style.animation='shake .4s ease';
    }
  } catch(err) {
    hideLoading();
    errEl.style.display='block';
    errEl.textContent='⚠ Connection error. Check your internet.';
    setTimeout(()=>errEl.style.display='none',4000);
  }
}

function startPresence() {
  if (!db || !CU) return;
  const presRef = db.ref(`${FB.presence}/${CU.username}`);
  presRef.set({ online:true, lastSeen:Date.now(), typing:false });
  presRef.onDisconnect().set({ online:false, lastSeen:Date.now(), typing:false });
}

async function doLogout() {
  stopInactivityWatch();
  // Clear presence
  if (db && CU) {
    try { await db.ref(`${FB.presence}/${CU.username}`).set({ online:false, lastSeen:Date.now(), typing:false }); } catch(e){}
  }
  detachListeners();
  clearSession();
  CU=null; selProj=null; page='dashboard';
  projects=[]; tasks=[]; docs=[]; archNotes=[]; projComments={}; groupChat=[];
  showScreen('s-login');
  $('l-user').value=''; $('l-pass').value='';
  _rmOn=false;
  const tog=$('rm-toggle'),knob=$('rm-knob'),lbl=$('rm-on');
  if(tog){tog.style.background='var(--bg5)';tog.style.borderColor='var(--border2)';}
  if(knob){knob.style.left='1px';knob.style.background='var(--text5)';}
  if(lbl)lbl.style.display='none';
}

function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s=>s.classList.remove('active'));
  $(id).classList.add('active');
}

// ── WELCOME ──────────────────────────────────────────────
function buildWelcome() {
  const u=CU;
  const mp=myProj(), mt=myTasks();
  const overdue=mt.filter(t=>t.deadline&&new Date(t.deadline)<new Date()&&t.status!=='Completed').length;
  const av_el=$('wc-av');
  av_el.textContent=u.avatar;
  av_el.style.background=`linear-gradient(145deg,${u.color},${u.color}cc)`;
  av_el.style.boxShadow=`0 12px 40px ${u.color}55`;
  $('wc-time').textContent=greetWord()+',';
  $('wc-greet').textContent=u.name.split(' ')[0]+' 👋';
  $('wc-full').textContent=u.role==='CEO'?'Sumukh Bharadwaj K S · CEO & Founder':`${u.name} · ${u.domain}`;
  const rb=$('wc-role-badge');
  rb.className='wc-role '+(isCEO()?'ceo':'team');
  rb.textContent=isCEO()?'👑 CEO · Full Access':`${u.domain}`;
  const facts=isCEO()?[
    {val:projects.length,lbl:'Projects'},
    {val:tasks.filter(t=>t.status==='In Progress').length,lbl:'Active'},
    {val:'₹'+projects.reduce((s,p)=>s+(p.revenue||0),0).toLocaleString('en-IN'),lbl:'Revenue'},
    {val:docs.length,lbl:'Docs'},
  ]:[
    {val:mp.length,lbl:'My Projects'},
    {val:mt.filter(t=>t.status==='In Progress').length,lbl:'Active'},
    {val:mt.filter(t=>t.status==='Completed').length,lbl:'Done'},
    {val:overdue>0?overdue:'✓',lbl:overdue>0?'Overdue':'On Track'},
  ];
  $('wc-facts').innerHTML=facts.map(f=>`<div class="wc-fact"><div class="wc-fact-val">${f.val}</div><div class="wc-fact-lbl">${f.lbl}</div></div>`).join('');
  const qList=QUOTES[u.domain]||QUOTES.Management;
  $('wc-quote').textContent='"'+qList[0]+'"';
  $('wc-date').textContent=fmtDT(new Date());
}

function enterApp() { showScreen('s-app'); initApp(); }

// ── APP INIT ─────────────────────────────────────────────
function initApp() {
  if (window.innerWidth<=768) $('menu-btn').style.display='flex';
  startInactivityWatch();
  renderSidebar();
  renderTopBar();
  navigate('dashboard');
}

function navigate(p,proj) {
  page=p;
  if(p!=='proj-detail') selProj=null;
  if(proj) selProj=proj;
  activeTab='overview'; taskExp={}; docOpen={};
  fStatus='All'; fVis='all'; fTask='All';
  renderTopBar(); renderSidebar(); updateBottomNav();
  const c=$('content');
  c.innerHTML='';
  if(p==='groupchat'){c.style.padding='0';c.style.overflow='hidden';}
  else{c.style.padding='';c.style.overflow='';}
  setTimeout(()=>renderContent(),10);
  closeSB();
}

function updateBottomNav() {
  ['dashboard','projects','tasks','groupchat'].forEach(id=>{
    const el=$('bn-'+id);
    if(el)el.classList.toggle('active',page===id||(id==='projects'&&page==='proj-detail'));
  });
}

// ── SIDEBAR ──────────────────────────────────────────────
function renderSidebar() {
  const navItems=[
    {id:'dashboard',icon:'◈',label:'Dashboard'},
    {id:'projects', icon:'⬡',label:'Projects'},
    {id:'tasks',    icon:'◎',label:'Tasks'},
    {id:'documents',icon:'▣',label:'Documents'},
    {id:'groupchat',icon:'💬',label:'Group Chat'},
    {id:'architecture',icon:'⬢',label:'Architecture'},
    ...(isCEO()?[
      {id:'finance', icon:'◆',label:'Finance', ceo:true},
      {id:'delivery',icon:'▶',label:'Delivery',ceo:true},
      {id:'users',   icon:'◉',label:'Users',   ceo:true},
    ]:[]),
  ];
  const isActive=id=>page===id||(page==='proj-detail'&&id==='projects');
  $('sb-nav').innerHTML=`
    <div class="sb-section">Navigation</div>
    ${navItems.map(n=>`
    <button class="nb${isActive(n.id)?' active':''}" onclick="navigate('${n.id}')">
      <span class="ni">${n.icon}</span>
      <span class="nl">${n.label}</span>
      ${n.ceo?`<span class="nt">CEO</span>`:''}
    </button>`).join('')}`;
  const col=CU.role==='CEO'?'#7b1fa2':CU.color;
  $('sb-user').innerHTML=`
    <div class="sb-user-row">
      ${av(CU.avatar,36,col)}
      <div style="min-width:0;">
        <div class="sb-uname">${CU.name.split(' ').slice(0,2).join(' ')}</div>
        <div class="sb-urole">${isCEO()?'👑 CEO':CU.domain}</div>
      </div>
    </div>
    <button class="btn-signout" onclick="doLogout()">Sign Out</button>`;
}

function renderTopBar() {
  const labels={dashboard:'Dashboard',projects:'Projects','proj-detail':selProj?`${selProj.id}`:'Project',tasks:'Tasks',documents:'Documents',finance:'Finance',users:'Users',delivery:'Delivery',architecture:'Architecture',groupchat:'Group Chat'};
  $('tb-title').textContent=labels[page]||'—';
  $('tb-date').textContent=new Date().toLocaleDateString('en-IN',{weekday:'short',day:'2-digit',month:'short',year:'numeric'});
  $('tb-right').innerHTML=`<span class="fb-status live">🔥 Live</span>${isCEO()?bdg('👑 CEO','#cc88e8',true):bdg(CU.domain.split(' ')[0],'#4ec4fc',true)}`;
}

function renderContent() {
  const c=$('content');
  const map={
    dashboard:renderDashboard,projects:renderProjects,'proj-detail':renderProjDetail,
    tasks:renderTasksPage,documents:renderDocsPage,groupchat:renderGroupChat,
    finance:isCEO()?renderFinance:renderDashboard,
    users:isCEO()?renderUsers:renderDashboard,
    delivery:isCEO()?renderDelivery:renderDashboard,
    architecture:renderArchitecture,
  };
  c.innerHTML=`<div class="page">${(map[page]||renderDashboard)()}</div>`;
  if(page==='groupchat') afterChatRender();
}

// ── DASHBOARD ────────────────────────────────────────────
function renderDashboard() {
  const mp=myProj(), mt=myTasks(), md=docs.filter(canSee);
  const stats=isCEO()?[
    {icon:'⬡',val:projects.length,lbl:'Total Projects',color:'var(--blue3)'},
    {icon:'◎',val:tasks.filter(t=>t.status==='In Progress').length,lbl:'Active Tasks',color:'var(--amber)'},
    {icon:'▣',val:docs.length,lbl:'Documents',color:'var(--green)'},
    {icon:'◆',val:'₹'+projects.reduce((s,p)=>s+(p.revenue||0),0).toLocaleString('en-IN'),lbl:'Revenue',color:'var(--purple)'},
  ]:[
    {icon:'⬡',val:mp.length,lbl:'My Projects',color:'var(--blue3)'},
    {icon:'◎',val:mt.filter(t=>t.status==='In Progress').length,lbl:'In Progress',color:'var(--amber)'},
    {icon:'✓',val:mt.filter(t=>t.status==='Completed').length,lbl:'Completed',color:'var(--green)'},
    {icon:'▣',val:md.length,lbl:'My Docs',color:'var(--purple)'},
  ];
  return `
  <div style="margin-bottom:20px;">
    <div style="font-family:var(--fd);font-weight:800;font-size:20px;color:var(--text);letter-spacing:-.03em;">${isCEO()?'👑 ':''}${greetWord()}, ${CU.name.split(' ')[0]}</div>
    <div style="font-size:12px;color:var(--text4);margin-top:4px;">${isCEO()?'Full system overview':'Your current work status'}</div>
  </div>
  <div class="g4" style="margin-bottom:22px;">
    ${stats.map(s=>`<div class="stat-card"><div class="stat-icon">${s.icon}</div><div class="stat-val" style="color:${s.color};">${s.val}</div><div class="stat-lbl">${s.lbl}</div></div>`).join('')}
  </div>
  <div class="g2">
    <div class="card" style="padding:16px 18px;">
      <div class="flex-between" style="margin-bottom:12px;">
        <div class="section-head" style="margin:0;">${isCEO()?'All Projects':'My Projects'}</div>
        <button class="btn-sm" onclick="navigate('projects')">View all →</button>
      </div>
      ${mp.slice(0,4).map(p=>`
      <div class="proj-card" style="padding:11px 13px;" onclick="openProj('${p.id}')">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <div style="min-width:0;"><div style="font-size:10px;color:var(--blue3);font-family:var(--fm);font-weight:600;margin-bottom:3px;">${p.id} · ${p.branch}</div>
          <div style="font-size:13px;font-weight:600;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${p.title}</div></div>
          ${bdg(p.status,SC[p.status]||'#78909c',true)}
        </div>
        <div style="margin-top:8px;">${pb(tasks.filter(t=>t.projectId===p.id).reduce((s,t,_,a)=>s+(a.length?t.progress/a.length:0),0)||0,SC[p.status]||'#1976d2')}</div>
      </div>`).join('')}
      ${mp.length===0?'<div class="empty"><span class="empty-icon">📂</span>No projects assigned</div>':''}
    </div>
    <div class="card" style="padding:16px 18px;">
      <div class="flex-between" style="margin-bottom:12px;">
        <div class="section-head" style="margin:0;">${isCEO()?'Recent Tasks':'My Tasks'}</div>
        <button class="btn-sm" onclick="navigate('tasks')">View all →</button>
      </div>
      ${mt.slice(0,4).map(t=>{
        const proj=projects.find(p=>p.id===t.projectId);
        return `<div style="padding:11px 12px;background:var(--bg4);border-radius:9px;margin-bottom:7px;border:1px solid var(--border);">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;gap:8px;">
            <div style="font-size:13px;font-weight:500;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${t.title}</div>
            ${bdg(t.status,SC[t.status]||'#78909c',true)}
          </div>
          <div style="font-size:10px;color:var(--text4);font-family:var(--fm);margin-bottom:6px;">${proj?.id||''} · Due ${fmtD(t.deadline)}</div>
          <div style="display:flex;align-items:center;gap:8px;">${pb(t.progress,SC[t.status]||'#1976d2')}<span style="font-size:10px;color:var(--blue3);font-family:var(--fm);flex-shrink:0;">${t.progress}%</span></div>
        </div>`;
      }).join('')}
      ${mt.length===0?'<div class="empty"><span class="empty-icon">✓</span>No tasks assigned</div>':''}
    </div>
  </div>`;
}

// ── PROJECTS ─────────────────────────────────────────────
function renderProjects() {
  const mp=myProj();
  const filt=fStatus==='All'?mp:mp.filter(p=>p.status===fStatus);
  return `
  <div class="flex-between" style="margin-bottom:16px;gap:10px;">
    <div class="filter-bar" style="margin:0;flex:1;flex-wrap:wrap;">
      ${['All','Created','Approved','In Development','Review','Delivered','Archived'].map(s=>`<button class="fbtn${fStatus===s?' on':''}" onclick="setFS('${s}')">${s}</button>`).join('')}
    </div>
    ${isCEO()?`<button class="btn-p" onclick="mCreateProj()" style="flex-shrink:0;">+ New Project</button>`:''}
  </div>
  ${filt.map(p=>projCard(p)).join('')}
  ${filt.length===0?'<div class="empty"><span class="empty-icon">🔍</span>No projects found</div>':''}`;
}
function setFS(s){fStatus=s;renderContent();}
function openProj(id){const p=projects.find(x=>x.id===id);if(p){selProj=p;page='proj-detail';activeTab='overview';renderTopBar();renderSidebar();updateBottomNav();renderContent();}}

function projCard(p) {
  const members=(p.assignedMembers||[]).slice(0,4).map((un,i)=>{const u=USERS[un];return u?`<div style="margin-left:${i>0?'-8px':'0'};z-index:${4-i};position:relative;" title="${u.name}">${av(u.avatar,26,u.color)}</div>`:''}).join('');
  const prog=tasks.filter(t=>t.projectId===p.id);
  const overall=prog.length?Math.round(prog.reduce((s,t)=>s+t.progress,0)/prog.length):0;
  return `
  <div class="proj-card" onclick="openProj('${p.id}')">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:5px;">
          <span style="font-size:11px;color:var(--blue3);font-family:var(--fm);font-weight:600;">${p.id}</span>
          ${bdg(p.status,SC[p.status]||'#78909c',true)}
          ${bdg(p.branch,'#546e8a',true)}
        </div>
        <div style="font-family:var(--fd);font-weight:700;font-size:14px;color:var(--text);margin-bottom:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${p.title}</div>
        <div style="font-size:12px;color:var(--text4);margin-bottom:9px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;">${p.description||'—'}</div>
        <div style="display:flex;align-items:center;gap:8px;">${pb(overall,SC[p.status]||'#1976d2')}<span style="font-size:10px;color:var(--text4);font-family:var(--fm);flex-shrink:0;">${overall}%</span></div>
        <div style="display:flex;gap:12px;font-size:11px;color:var(--text4);font-family:var(--fm);flex-wrap:wrap;margin-top:7px;">
          <span>📅 ${fmtD(p.deadline)}</span>
          <span>👥 ${(p.assignedMembers||[]).length}</span>
          ${isCEO()?`<span style="color:var(--purple);">₹${(p.budget||0).toLocaleString('en-IN')}</span>`:''}
        </div>
      </div>
      <div style="display:flex;align-items:center;flex-shrink:0;margin-top:4px;">${members}</div>
    </div>
  </div>`;
}

// ── PROJECT DETAIL ────────────────────────────────────────
function renderProjDetail() {
  if(!selProj)return'<div class="empty">No project selected</div>';
  const p=selProj;
  const tabs=['overview','tasks','documents','comments'];
  if(isCEO())tabs.push('payments');
  let body='';
  if(activeTab==='overview')body=tabOverview(p);
  else if(activeTab==='tasks')body=tabTasks(p);
  else if(activeTab==='documents')body=tabDocs(p);
  else if(activeTab==='comments')body=tabComments(p);
  else if(activeTab==='payments')body=tabPayments(p);
  return `
  <button class="back-btn" onclick="navigate('projects')">← Back</button>
  <div class="flex-between" style="margin-bottom:16px;">
    <div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px;">
        <span style="font-family:var(--fm);font-size:11px;color:var(--blue3);font-weight:600;">${p.id}</span>
        ${bdg(p.status,SC[p.status]||'#78909c')}
        ${bdg(p.branch,'#546e8a',true)}
      </div>
      <h2 style="font-family:var(--fd);font-weight:800;font-size:17px;color:var(--text);letter-spacing:-.02em;">${p.title}</h2>
    </div>
    <div style="display:flex;gap:7px;flex-wrap:wrap;">
      ${isCEO()?`<button class="btn-s" onclick="mStatusChange()" style="font-size:12px;">Status</button>
      <button class="btn-s" onclick="mEditProject('${p.id}')" style="font-size:12px;">✏ Edit</button>
      <button class="btn-s" onclick="deleteProject('${p.id}')" style="font-size:12px;color:var(--red);">🗑</button>`:''}
      <button class="btn-s" onclick="mUploadDoc('${p.id}')" style="font-size:12px;">+ Upload</button>
      ${isCEO()?`<button class="btn-p" onclick="mCreateTask('${p.id}')" style="font-size:12px;">+ Task</button>`:''}
    </div>
  </div>
  <div class="tabs">
    ${tabs.map(t=>`<button class="tab${activeTab===t?' on':''}" onclick="setTab('${t}')">${t}</button>`).join('')}
  </div>
  ${body}`;
}
function setTab(t){activeTab=t;renderContent();}

function tabOverview(p){
  const pt=tasks.filter(t=>t.projectId===p.id);
  const overall=pt.length?Math.round(pt.reduce((s,t)=>s+t.progress,0)/pt.length):0;
  return `
  <div class="g2">
    <div class="card" style="padding:16px 18px;">
      <div class="section-head">Project Info</div>
      <div class="irow"><span class="ilabel">Type</span><span class="ival">${p.type||'—'}</span></div>
      <div class="irow"><span class="ilabel">Branch</span><span class="ival">${p.branch||'—'}</span></div>
      <div class="irow"><span class="ilabel">Year</span><span class="ival">${p.year||'—'}</span></div>
      <div class="irow"><span class="ilabel">Created</span><span class="ival">${fmtD(p.createdAt)}</span></div>
      <div class="irow"><span class="ilabel">Deadline</span><span class="ival">${fmtD(p.deadline)}</span></div>
      ${isCEO()?`<div class="irow"><span class="ilabel">Budget</span><span class="ival" style="color:var(--purple);">₹${(p.budget||0).toLocaleString('en-IN')}</span></div>`:''}
      <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);">
        <div style="font-size:10px;color:var(--text4);font-family:var(--fm);text-transform:uppercase;margin-bottom:6px;">Overall Progress</div>
        ${pb(overall,'#4ec4fc')}
        <div style="text-align:right;font-size:11px;color:var(--blue3);font-family:var(--fm);margin-top:4px;">${overall}%</div>
      </div>
    </div>
    <div class="card" style="padding:16px 18px;">
      <div class="section-head">Team</div>
      ${(p.assignedMembers||[]).map(un=>{const u=USERS[un];return u?`<div style="display:flex;align-items:center;gap:10px;padding:9px 11px;background:var(--bg4);border-radius:9px;margin-bottom:7px;border:1px solid var(--border);">${av(u.avatar,30,u.color)}<div><div style="font-size:13px;font-weight:500;color:var(--text2);">${u.name}</div><div style="font-size:10px;color:var(--text4);font-family:var(--fm);">${u.domain}</div></div></div>`:''}).join('')}
      ${(p.assignedMembers||[]).length===0?'<div style="color:var(--text5);font-size:12px;">No members assigned</div>':''}
    </div>
    <div class="card" style="padding:16px 18px;grid-column:span 2;">
      <div class="section-head">Description & Requirements</div>
      <p style="font-size:13px;color:var(--text3);line-height:1.75;margin-bottom:12px;">${p.description||'—'}</p>
      <div style="font-size:10px;color:var(--text4);font-family:var(--fm);text-transform:uppercase;margin-bottom:6px;">Requirements</div>
      <p style="font-size:13px;color:var(--text3);line-height:1.7;">${p.requirements||'—'}</p>
    </div>
  </div>`;
}

function tabTasks(p){
  const pt=isCEO()?tasks.filter(t=>t.projectId===p.id):tasks.filter(t=>t.projectId===p.id&&t.assignedTo===CU.username);
  if(!pt.length)return`<div class="empty"><span class="empty-icon">📋</span>${isCEO()?'No tasks yet. Add one above.':'No tasks assigned to you here.'}</div>`;
  return pt.map(t=>taskCard(t)).join('');
}

function taskCard(t){
  const u=USERS[t.assignedTo];
  const canEdit=isCEO()||t.assignedTo===CU.username;
  const exp=taskExp[t.id];
  const overdueFlag=t.deadline&&new Date(t.deadline)<new Date()&&t.status!=='Completed';
  return `
  <div class="task-card">
    <div class="tc-head" onclick="toggleTE('${t.id}')">
      <div style="display:flex;align-items:center;gap:10px;">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:4px;">
            <span style="font-size:10px;color:var(--blue3);font-family:var(--fm);font-weight:600;">${t.id}</span>
            ${bdg(t.status,SC[t.status]||'#78909c',true)}
            ${overdueFlag?bdg('Overdue','#f04545',true):''}
          </div>
          <div style="font-size:14px;font-weight:600;color:var(--text2);margin-bottom:7px;">${t.title}</div>
          <div style="display:flex;align-items:center;gap:8px;">${pb(t.progress,SC[t.status]||'#1976d2')}<span style="font-size:10px;color:var(--blue3);font-family:var(--fm);flex-shrink:0;">${t.progress}%</span></div>
        </div>
        <div style="display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex-shrink:0;">
          ${u?av(u.avatar,30,u.color):''}
          <span style="font-size:10px;color:var(--text5);font-family:var(--fm);">Due ${fmtD(t.deadline)}</span>
        </div>
        <span style="color:var(--text5);font-size:12px;margin-left:6px;">${exp?'▲':'▼'}</span>
      </div>
    </div>
    ${exp?`
    <div class="tc-body">
      ${canEdit?`
      <div style="margin-bottom:14px;padding:12px 13px;background:var(--bg4);border-radius:9px;border:1px solid var(--border);">
        <div style="font-size:10px;color:var(--text4);font-family:var(--fm);text-transform:uppercase;margin-bottom:8px;">Update Progress</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <input type="range" min="0" max="100" value="${t.progress}" oninput="previewProgress('${t.id}',this.value)" style="flex:1;accent-color:var(--blue2);height:20px;">
          <span id="prog-${t.id}" style="font-size:12px;color:var(--blue3);font-family:var(--fm);width:38px;flex-shrink:0;">${t.progress}%</span>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          ${['Not Started','In Progress','Review','Completed'].map(s=>`<button onclick="updTS('${t.id}','${s}')" style="padding:7px 11px;border-radius:6px;font-size:11px;font-family:var(--fm);background:${t.status===s?'var(--blue)':'var(--bg3)'};color:${t.status===s?'#fff':'var(--text3)'};border:1px solid ${t.status===s?'var(--blue2)':'var(--border2)'};min-height:36px;">${s}</button>`).join('')}
        </div>
        <div style="display:flex;justify-content:flex-end;margin-top:10px;">
          <button class="btn-p" style="font-size:12px;padding:8px 16px;" onclick="saveProgress('${t.id}')">Save Progress</button>
        </div>
      </div>
      ${isCEO()?`<div style="display:flex;justify-content:flex-end;margin-bottom:12px;"><button class="btn-s" onclick="deleteTask('${t.id}')" style="color:var(--red);font-size:12px;">🗑 Delete Task</button></div>`:''}
      `:''}
      <div style="font-size:10px;color:var(--text4);font-family:var(--fm);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">Internal Notes</div>
      ${(t.notes||[]).map(n=>`<div class="note-item"><div style="display:flex;justify-content:space-between;margin-bottom:4px;flex-wrap:wrap;gap:6px;"><span style="font-size:11px;font-weight:600;color:var(--text2);">${n.name}</span><span style="font-size:10px;color:var(--text5);font-family:var(--fm);">${n.ts}</span></div><div style="font-size:12px;color:var(--text3);line-height:1.55;">${n.text}</div></div>`).join('')}
      <div style="display:flex;gap:8px;margin-top:8px;">
        <input class="inp-sm" id="ni-${t.id}" placeholder="Write a note…" style="flex:1;" onkeydown="if(event.key==='Enter')addNote('${t.id}')">
        <button class="btn-p" style="padding:10px 14px;font-size:12px;" onclick="addNote('${t.id}')">Add</button>
      </div>
    </div>`:''}
  </div>`;
}

let _tempProgress = {};
function previewProgress(id,val) {
  _tempProgress[id]=Number(val);
  const el=document.getElementById('prog-'+id);
  if(el) el.textContent=val+'%';
}
async function saveProgress(id) {
  const val=_tempProgress[id];
  if(val===undefined) return;
  await db.ref(`${FB.tasks}/${id}/progress`).set(val);
  notify('Progress saved: '+val+'%');
}

function tabDocs(p){
  const pd=docs.filter(d=>d.projectId===p.id&&canSee(d));
  if(!pd.length)return`<div class="empty"><span class="empty-icon">📁</span>No documents yet. Tap "+ Upload" above.</div>`;
  return pd.map(d=>docCard(d)).join('');
}

function docCard(d){
  const vc=VC[d.visibility]||VC.shared;
  const t=tasks.find(x=>x.id===d.taskId);
  const u=USERS[d.uploadedBy];
  const op=docOpen[d.id];
  return `
  <div class="doc-card">
    <div style="display:flex;align-items:flex-start;gap:12px;">
      <span style="font-size:28px;margin-top:2px;flex-shrink:0;">${fi(d.type)}</span>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:5px;">
          <span style="font-size:13px;font-weight:600;color:var(--text2);word-break:break-all;">${d.name}</span>
          ${d.approved?bdg('✓ Approved','#56c26a',true):''}
          ${d.locked?bdg('🔒 Locked','#f04545',true):''}
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px;">
          <span style="font-size:10px;background:${vc.c}1a;color:${vc.c};border:1px solid ${vc.c}3a;padding:2px 8px;border-radius:4px;font-family:var(--fm);font-weight:600;">${vc.i} ${vc.l}</span>
          <span style="font-size:10px;color:var(--text4);font-family:var(--fm);">v${d.version||1} · ${d.size||'—'}</span>
          <span style="font-size:10px;color:var(--text5);font-family:var(--fm);">by ${u?.name?.split(' ')[0]||d.uploadedBy}</span>
          ${t?`<span style="font-size:10px;color:var(--text4);font-family:var(--fm);">📌 ${t.title}</span>`:''}
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
          <button class="btn-icon" onclick="toggleDC('${d.id}')" style="font-size:12px;">💬 ${(d.comments||[]).length}</button>
          ${d.hasFile?`<button class="btn-icon" onclick="downloadDoc('${d.id}')" style="font-size:12px;color:var(--green);">⬇ Download</button>`:''}
          ${isCEO()?`
          <button class="btn-icon" title="${d.approved?'Revoke':'Approve'}" onclick="togApprove('${d.id}')" style="color:${d.approved?'var(--green)':'var(--text3)'};">✓</button>
          <button class="btn-icon" title="${d.locked?'Unlock':'Lock'}" onclick="togLock('${d.id}')" style="color:${d.locked?'var(--red)':'var(--text3)'};">🔒</button>
          <select onchange="chVis('${d.id}',this.value)" style="background:var(--bg4);border:1px solid var(--border2);border-radius:6px;color:var(--text3);font-size:11px;padding:7px 8px;font-family:var(--fm);min-height:36px;">
            <option value="ceo-only"${d.visibility==='ceo-only'?' selected':''}>👑 CEO</option>
            <option value="team-only"${d.visibility==='team-only'?' selected':''}>👥 Team</option>
            <option value="shared"${d.visibility==='shared'?' selected':''}>🌐 Shared</option>
          </select>
          <button class="btn-icon" onclick="delDoc('${d.id}')" style="color:var(--red);">🗑</button>`:''}
        </div>
      </div>
    </div>
    ${op?`
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);">
      ${(d.comments||[]).map(c=>`<div class="note-item" style="margin-bottom:7px;"><div style="display:flex;justify-content:space-between;margin-bottom:3px;flex-wrap:wrap;gap:6px;"><span style="font-size:11px;font-weight:600;color:var(--text2);">${c.name}</span><span style="font-size:10px;color:var(--text5);font-family:var(--fm);">${c.ts}</span></div><div style="font-size:12px;color:var(--text3);">${c.text}</div></div>`).join('')}
      <div style="display:flex;gap:8px;">
        <input class="inp-sm" id="dc-${d.id}" placeholder="Add a comment…" style="flex:1;" onkeydown="if(event.key==='Enter')addDC('${d.id}')">
        <button class="btn-p" style="padding:10px 14px;font-size:12px;" onclick="addDC('${d.id}')">Send</button>
      </div>
    </div>`:''}
  </div>`;
}

function tabComments(p){
  const cm=projComments[p.id]||[];
  return `
  <div style="margin-bottom:12px;">
    ${cm.map(c=>`<div class="cmt-item">${av(USERS[c.by]?.avatar||'?',34,USERS[c.by]?.color||'#1565c0')}<div style="flex:1;min-width:0;"><div style="display:flex;justify-content:space-between;margin-bottom:5px;flex-wrap:wrap;gap:6px;"><span style="font-size:12px;font-weight:600;color:var(--text2);">${c.name}</span><span style="font-size:10px;color:var(--text5);font-family:var(--fm);">${c.ts}</span></div><div style="font-size:13px;color:var(--text3);line-height:1.65;">${c.text}</div></div></div>`).join('')}
    ${cm.length===0?'<div class="empty" style="margin-bottom:12px;"><span class="empty-icon">💬</span>No comments yet.</div>':''}
  </div>
  <div style="display:flex;gap:10px;">
    ${av(CU.avatar,36,CU.color)}
    <input class="inp-sm" id="pc-inp" placeholder="Write a comment…" style="flex:1;" onkeydown="if(event.key==='Enter')addPC('${p.id}')">
    <button class="btn-p" onclick="addPC('${p.id}')">Post</button>
  </div>`;
}

function tabPayments(p){
  const paid=(p.payments||[]).filter(x=>x.status==='Paid').reduce((s,x)=>s+Number(x.amount),0);
  const pend=(p.payments||[]).filter(x=>x.status==='Pending').reduce((s,x)=>s+Number(x.amount),0);
  const profit=(p.revenue||0)-(p.cost||0);
  return `
  <div class="g3" style="margin-bottom:16px;">
    <div class="stat-card"><div class="stat-icon">💰</div><div class="stat-val" style="color:var(--blue3);">₹${(p.budget||0).toLocaleString('en-IN')}</div><div class="stat-lbl">Budget</div></div>
    <div class="stat-card"><div class="stat-icon">✅</div><div class="stat-val" style="color:var(--green);">₹${paid.toLocaleString('en-IN')}</div><div class="stat-lbl">Received</div></div>
    <div class="stat-card"><div class="stat-icon">⏳</div><div class="stat-val" style="color:var(--amber);">₹${pend.toLocaleString('en-IN')}</div><div class="stat-lbl">Pending</div></div>
  </div>
  <div class="g2" style="margin-bottom:20px;">
    <div class="stat-card"><div class="stat-icon">📈</div><div class="stat-val" style="color:var(--purple);">₹${(p.revenue||0).toLocaleString('en-IN')}</div><div class="stat-lbl">Revenue</div></div>
    <div class="stat-card"><div class="stat-icon">💹</div><div class="stat-val" style="color:${profit>=0?'var(--green)':'var(--red)'};">₹${profit.toLocaleString('en-IN')}</div><div class="stat-lbl">Net Profit</div></div>
  </div>
  <div class="flex-between" style="margin-bottom:12px;">
    <div class="section-head" style="margin:0;">Payment Stages</div>
    <button class="btn-p" onclick="mAddPayment('${p.id}')">+ Add Stage</button>
  </div>
  ${(p.payments||[]).map((pay,i)=>`
  <div class="pay-row">
    <div>
      <div style="font-size:13px;font-weight:600;color:var(--text2);">${pay.stage}</div>
      ${pay.date?`<div style="font-size:11px;color:var(--text4);font-family:var(--fm);margin-top:2px;">${fmtD(pay.date)}</div>`:''}
    </div>
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="font-family:var(--fd);font-weight:700;font-size:14px;color:var(--purple);">₹${Number(pay.amount).toLocaleString('en-IN')}</span>
      <button onclick="togPay('${p.id}',${i})" style="padding:8px 13px;border-radius:6px;font-size:11px;font-family:var(--fm);background:${pay.status==='Paid'?'rgba(22,80,28,.5)':'var(--bg4)'};border:1px solid ${pay.status==='Paid'?'rgba(86,194,106,.3)':'var(--border2)'};color:${pay.status==='Paid'?'var(--green)':'var(--text3)'};min-height:38px;">${pay.status==='Paid'?'✓ Paid':'Pending'}</button>
    </div>
  </div>`).join('')}`;
}

// ── TASKS PAGE ────────────────────────────────────────────
function renderTasksPage(){
  const mt=myTasks();
  const filt=fTask==='All'?mt:mt.filter(t=>t.status===fTask);
  return `
  <div class="filter-bar">
    ${['All','Not Started','In Progress','Review','Completed'].map(s=>`<button class="fbtn${fTask===s?' on':''}" onclick="setFT('${s}')">${s}</button>`).join('')}
  </div>
  ${filt.map(t=>{
    const proj=projects.find(p=>p.id===t.projectId);
    const overdueFlag=t.deadline&&new Date(t.deadline)<new Date()&&t.status!=='Completed';
    const canEdit=isCEO()||t.assignedTo===CU.username;
    return `
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r12);padding:14px 16px;margin-bottom:9px;">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:7px;">
        <span style="font-size:10px;color:var(--blue3);font-family:var(--fm);font-weight:600;">${t.id}</span>
        ${bdg(t.status,SC[t.status]||'#78909c',true)}
        ${proj?bdg(proj.id,'#546e8a',true):''}
        ${overdueFlag?bdg('Overdue','#f04545',true):''}
        <span style="margin-left:auto;font-size:11px;color:var(--text4);font-family:var(--fm);">Due ${fmtD(t.deadline)}</span>
      </div>
      <div style="font-size:14px;font-weight:600;color:var(--text2);margin-bottom:9px;">${t.title}</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:${canEdit?'10px':'0'};">${pb(t.progress,SC[t.status]||'#1976d2')}<span style="font-size:10px;color:var(--blue3);font-family:var(--fm);flex-shrink:0;width:34px;">${t.progress}%</span></div>
      ${canEdit?`<input type="range" min="0" max="100" value="${t.progress}" onchange="updTP('${t.id}',this.value)" style="width:100%;accent-color:var(--blue2);height:24px;">`:''}
    </div>`;
  }).join('')}
  ${filt.length===0?'<div class="empty"><span class="empty-icon">✓</span>No tasks found</div>':''}`;
}
function setFT(s){fTask=s;renderContent();}

// ── DOCUMENTS PAGE ────────────────────────────────────────
function renderDocsPage(){
  const myD=docs.filter(canSee);
  const filt=fVis==='all'?myD:myD.filter(d=>d.visibility===fVis);
  return `
  <div class="flex-between" style="margin-bottom:16px;">
    <div class="filter-bar" style="margin:0;flex:1;">
      ${[['all','All'],['ceo-only','👑 CEO'],['team-only','👥 Team'],['shared','🌐 Shared']].filter(([v])=>isCEO()||v!=='ceo-only').map(([v,l])=>`<button class="fbtn${fVis===v?' on':''}" onclick="setFV('${v}')">${l}</button>`).join('')}
    </div>
    <button class="btn-p" onclick="mUploadDoc(null)" style="flex-shrink:0;">+ Upload</button>
  </div>
  ${filt.map(d=>docCard(d)).join('')}
  ${filt.length===0?'<div class="empty"><span class="empty-icon">📁</span>No documents found</div>':''}`;
}
function setFV(v){fVis=v;renderContent();}

// ── FINANCE ───────────────────────────────────────────────
function renderFinance(){
  const totR=projects.reduce((s,p)=>s+(p.revenue||0),0);
  const totC=projects.reduce((s,p)=>s+(p.cost||0),0);
  const totP=totR-totC;
  const totRcv=projects.reduce((s,p)=>s+(p.payments||[]).filter(x=>x.status==='Paid').reduce((ss,x)=>ss+Number(x.amount),0),0);
  return `
  <div class="g4" style="margin-bottom:22px;">
    <div class="stat-card"><div class="stat-icon">📈</div><div class="stat-val" style="color:var(--blue3);">₹${totR.toLocaleString('en-IN')}</div><div class="stat-lbl">Total Revenue</div></div>
    <div class="stat-card"><div class="stat-icon">📉</div><div class="stat-val" style="color:var(--red);">₹${totC.toLocaleString('en-IN')}</div><div class="stat-lbl">Total Cost</div></div>
    <div class="stat-card"><div class="stat-icon">💹</div><div class="stat-val" style="color:var(--green);">₹${totP.toLocaleString('en-IN')}</div><div class="stat-lbl">Net Profit</div></div>
    <div class="stat-card"><div class="stat-icon">✅</div><div class="stat-val" style="color:var(--amber);">₹${totRcv.toLocaleString('en-IN')}</div><div class="stat-lbl">Received</div></div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Project</th><th>Status</th><th>Budget</th><th>Revenue</th><th>Cost</th><th>Profit</th><th>Received</th></tr></thead>
      <tbody>
      ${projects.map(p=>{
        const rcv=(p.payments||[]).filter(x=>x.status==='Paid').reduce((s,x)=>s+Number(x.amount),0);
        const prf=(p.revenue||0)-(p.cost||0);
        return `<tr>
          <td><div style="font-weight:600;color:var(--text2);">${p.title}</div><div style="font-size:10px;color:var(--text5);font-family:var(--fm);margin-top:2px;">${p.id}</div></td>
          <td>${bdg(p.status,SC[p.status]||'#78909c',true)}</td>
          <td style="font-family:var(--fm);color:var(--text2);">₹${(p.budget||0).toLocaleString('en-IN')}</td>
          <td style="font-family:var(--fm);color:var(--blue3);">₹${(p.revenue||0).toLocaleString('en-IN')}</td>
          <td style="font-family:var(--fm);color:var(--red);">₹${(p.cost||0).toLocaleString('en-IN')}</td>
          <td style="font-family:var(--fm);color:${prf>=0?'var(--green)':'var(--red)'};">₹${prf.toLocaleString('en-IN')}</td>
          <td style="font-family:var(--fm);color:var(--amber);">₹${rcv.toLocaleString('en-IN')}</td>
        </tr>`;}).join('')}
      </tbody>
    </table>
  </div>`;
}

// ── USERS ─────────────────────────────────────────────────
function renderUsers(){
  return `
  <div class="flex-end" style="margin-bottom:16px;">
    <button class="btn-p" onclick="mCreateUser()">+ Create Account</button>
  </div>
  ${Object.entries(USERS).map(([un,u])=>`
  <div style="display:flex;align-items:center;gap:12px;padding:14px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r12);margin-bottom:9px;opacity:${u.enabled===false?.5:1};">
    ${av(u.avatar,38,u.color||'#1565c0')}
    <div style="flex:1;min-width:0;">
      <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:4px;">
        <span style="font-size:13px;font-weight:600;color:var(--text2);">${u.name}</span>
        ${u.role==='CEO'?bdg('👑 CEO','#cc88e8',true):''}
        ${bdg((u.domain||'').split(' ')[0],'#546e8a',true)}
        ${u.enabled===false?bdg('Disabled','#f04545',true):''}
      </div>
      <div style="font-size:11px;color:var(--text4);font-family:var(--fm);">${un}</div>
      <div style="font-size:11px;color:var(--text4);font-family:var(--fm);">${u.domain||'—'}</div>
      <div style="font-size:11px;color:var(--text5);font-family:var(--fm);margin-top:1px;">Password: <span style="color:var(--text4);">${u.password}</span></div>
    </div>
    ${u.role!=='CEO'?`
    <div style="display:flex;flex-direction:column;gap:7px;flex-shrink:0;">
      <button class="btn-sm" onclick="mEditUser('${un}')">Edit</button>
      <button class="btn-sm" onclick="togUser('${un}')" style="color:${u.enabled===false?'var(--green)':'var(--red)'};border-color:${u.enabled===false?'var(--green)':'var(--red)'};">${u.enabled===false?'Enable':'Disable'}</button>
      <button class="btn-sm" onclick="deleteUser('${un}')" style="color:var(--red);border-color:var(--red);">Delete</button>
    </div>`:''}
  </div>`).join('')}`;
}

// ── DELIVERY ──────────────────────────────────────────────
function renderDelivery(){
  const dp=projects.filter(p=>p.status==='Review'||p.status==='Delivered');
  return `
  <div style="font-size:11px;color:var(--text4);font-family:var(--fm);text-transform:uppercase;letter-spacing:.07em;margin-bottom:14px;">Projects ready for delivery or archival</div>
  ${dp.map(p=>{
    const pd=docs.filter(d=>d.projectId===p.id&&d.visibility==='shared');
    return `<div class="card" style="padding:16px 20px;margin-bottom:12px;">
      <div class="flex-between">
        <div>
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px;"><span style="font-size:11px;color:var(--blue3);font-family:var(--fm);font-weight:600;">${p.id}</span>${bdg(p.status,SC[p.status]||'#78909c')}</div>
          <div style="font-family:var(--fd);font-weight:700;font-size:14px;color:var(--text);margin-bottom:5px;">${p.title}</div>
          <div style="font-size:12px;color:var(--text4);font-family:var(--fm);">📂 ${pd.length} shared docs · Deadline: ${fmtD(p.deadline)}</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:7px;">
          ${p.status==='Review'?`<button class="btn-p" onclick="markDel('${p.id}')">Mark Delivered ✓</button>`:''}
          ${p.status==='Delivered'?`<button class="btn-s" onclick="archProj('${p.id}')">Archive →</button>`:''}
        </div>
      </div>
    </div>`;}).join('')}
  ${dp.length===0?'<div class="empty"><span class="empty-icon">📦</span>No projects in Review or Delivered state</div>':''}`;
}

// ── GROUP CHAT ────────────────────────────────────────────
function renderGroupChat() {
  return `
  <div id="chat-wrap">
    <div style="padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg2);display:flex;align-items:center;gap:8px;flex-shrink:0;">
      <span style="font-family:var(--fd);font-weight:700;font-size:15px;">💬 Team Chat</span>
      <span class="badge" style="background:rgba(86,194,106,.2);color:var(--green);border:1px solid rgba(86,194,106,.4);display:flex;align-items:center;gap:4px;"><span class="chat-online-dot"></span>Live</span>
    </div>
    <div id="chat-messages" style="flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:10px;">
      ${buildChatMessages()}
    </div>
    <div id="chat-input-bar">
      ${av(CU.avatar,36,CU.color)}
      <textarea class="chat-typing-area" id="chat-inp" placeholder="Type a message… (Enter to send)" rows="1"
        oninput="autoResizeChat(this)"
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat();}"></textarea>
      <button class="chat-send-btn" onclick="sendChat()">➤</button>
    </div>
  </div>`;
}

function buildChatMessages() {
  const typingHtml = buildTypingIndicator();
  if (!groupChat.length && !typingHtml) {
    return `<div style="flex:1;display:flex;align-items:center;justify-content:center;"><div style="text-align:center;color:var(--text5);"><div style="font-size:48px;margin-bottom:16px;">💬</div><div style="font-size:16px;font-weight:600;color:var(--text2);margin-bottom:8px;">Team Group Chat</div><div style="font-size:13px;font-family:var(--fm);color:var(--text4);">Start the conversation!</div></div></div>`;
  }
  let html='';
  let lastDate='';
  groupChat.forEach(msg=>{
    const msgDate=new Date(msg.ts).toLocaleDateString('en-IN',{weekday:'long',day:'2-digit',month:'long'});
    if(msgDate!==lastDate){ html+=`<div class="chat-date-divider">${msgDate}</div>`; lastDate=msgDate; }
    const mine=msg.by===CU.username;
    const u=USERS[msg.by];
    const timeStr=formatMsgTime(msg.ts);
    html+=`
    <div class="chat-msg ${mine?'mine':'theirs'}">
      ${!mine?`<div>${av(u?.avatar||'?',32,u?.color||'#1565c0')}</div>`:''}
      <div style="max-width:75%;min-width:0;">
        ${!mine?`<div class="chat-name-badge">${u?.name?.split(' ')[0]||msg.by} · ${u?.domain||''}</div>`:''}
        <div class="chat-bubble">${escapeHtml(msg.text)}</div>
        <div class="chat-meta">${timeStr}</div>
      </div>
    </div>`;
  });
  if(typingHtml) html+=typingHtml;
  return html;
}

function formatMsgTime(ts) {
  const diff=Date.now()-ts;
  const m=Math.floor(diff/60000);
  if(m<1)return'Just now';
  if(m<60)return m+'m ago';
  if(m<1440)return Math.floor(m/60)+'h ago';
  return new Date(ts).toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',hour12:true});
}

function buildTypingIndicator() {
  const others=Object.keys(typingUsers).filter(u=>u!==CU.username);
  if(!others.length)return'';
  const names=others.map(u=>USERS[u]?.name?.split(' ')[0]||u).join(', ');
  return `<div class="chat-typing-indicator">${names} ${others.length===1?'is':'are'} typing<div class="chat-typing-dots"><div class="chat-typing-dot"></div><div class="chat-typing-dot"></div><div class="chat-typing-dot"></div></div></div>`;
}

function autoResizeChat(el) {
  el.style.height='auto';
  el.style.height=Math.min(el.scrollHeight,120)+'px';
  // typing presence
  if(db && CU) {
    db.ref(`${FB.presence}/${CU.username}`).set({online:true,lastSeen:Date.now(),typing:true});
    clearTimeout(typingTimeout);
    typingTimeout=setTimeout(()=>{
      if(db&&CU) db.ref(`${FB.presence}/${CU.username}`).set({online:true,lastSeen:Date.now(),typing:false});
    },2000);
  }
}

async function sendChat() {
  const inp=$('chat-inp');
  if(!inp)return;
  const text=inp.value.trim();
  if(!text)return;
  inp.value='';
  inp.style.height='auto';
  if(db&&CU) db.ref(`${FB.presence}/${CU.username}`).set({online:true,lastSeen:Date.now(),typing:false});
  await db.ref(FB.chat).push({by:CU.username,name:CU.name,text,ts:Date.now()});
  const msgArea=$('chat-messages');
  if(msgArea) setTimeout(()=>{ msgArea.scrollTop=msgArea.scrollHeight; },100);
}

function afterChatRender() {
  setTimeout(()=>{
    const msgArea=$('chat-messages');
    if(msgArea){ msgArea.scrollTop=msgArea.scrollHeight; msgArea.style.scrollBehavior='smooth'; }
    const inp=$('chat-inp');
    if(inp) inp.focus();
  },100);
}

// ── ARCHITECTURE ──────────────────────────────────────────
function renderArchitecture(){
  return `
  ${isCEO()?`<div class="flex-end" style="margin-bottom:16px;"><button class="btn-p" onclick="mNewNote()">+ Add Note</button></div>`:''}
  ${archNotes.length===0?'<div class="empty"><span class="empty-icon">⬢</span>No architecture notes yet.</div>':''}
  ${archNotes.map(n=>`
  <div class="card" style="padding:16px 20px;margin-bottom:14px;">
    <div class="flex-between" style="margin-bottom:10px;">
      <div>
        <div style="font-family:var(--fd);font-weight:700;font-size:14px;color:var(--text);margin-bottom:4px;">${n.title}</div>
        <div style="font-size:11px;color:var(--text5);font-family:var(--fm);">by ${USERS[n.editedBy]?.name?.split(' ')[0]||n.editedBy} · ${n.ts}</div>
      </div>
      ${isCEO()?`<div style="display:flex;gap:6px;"><button class="btn-s" onclick="mEditNote('${n.id}')">Edit</button><button class="btn-icon" onclick="delNote('${n.id}')" style="color:var(--red);">🗑</button></div>`:''}
    </div>
    <pre style="font-size:13px;color:var(--text3);line-height:1.8;white-space:pre-wrap;font-family:var(--fm);">${escapeHtml(n.content)}</pre>
  </div>`).join('')}`;
}

// ══════════════════════════════════════════════════════════
//  FIREBASE WRITE ACTIONS
// ══════════════════════════════════════════════════════════

// TASK ACTIONS
function toggleTE(id){taskExp[id]=!taskExp[id];renderContent();}
function toggleDC(id){docOpen[id]=!docOpen[id];renderContent();}

async function updTP(id,val) {
  await db.ref(`${FB.tasks}/${id}/progress`).set(Number(val));
}
async function updTS(id,s) {
  await db.ref(`${FB.tasks}/${id}/status`).set(s);
  if(s==='Completed') await db.ref(`${FB.tasks}/${id}/progress`).set(100);
  notify('Status: '+s);
}

async function addNote(tid) {
  const inp=document.getElementById('ni-'+tid);
  if(!inp||!inp.value.trim())return;
  const t=tasks.find(x=>x.id===tid);
  if(!t)return;
  const notes=[...(t.notes||[]),{text:inp.value.trim(),by:CU.username,name:CU.name,ts:new Date().toLocaleString('en-IN')}];
  await db.ref(`${FB.tasks}/${tid}/notes`).set(notes);
  notify('Note added');
}

async function deleteTask(id) {
  if(!confirm('Delete this task permanently?'))return;
  await db.ref(`${FB.tasks}/${id}`).remove();
  notify('Task deleted');
}

// DOC ACTIONS
async function addDC(did) {
  const inp=document.getElementById('dc-'+did);
  if(!inp||!inp.value.trim())return;
  const d=docs.find(x=>x.id===did);
  if(!d)return;
  const comments=[...(d.comments||[]),{text:inp.value.trim(),by:CU.username,name:CU.name,ts:new Date().toLocaleString('en-IN')}];
  await db.ref(`${FB.docs}/${did}/comments`).set(comments);
}

async function togApprove(id) {
  const d=docs.find(x=>x.id===id); if(!d)return;
  await db.ref(`${FB.docs}/${id}/approved`).set(!d.approved);
  notify(d.approved?'Approval revoked':'Document approved');
}
async function togLock(id) {
  const d=docs.find(x=>x.id===id); if(!d)return;
  await db.ref(`${FB.docs}/${id}/locked`).set(!d.locked);
  notify(d.locked?'Unlocked':'Locked');
}
async function chVis(id,vis) {
  await db.ref(`${FB.docs}/${id}/visibility`).set(vis);
  notify('Visibility changed');
}
async function delDoc(id) {
  if(!confirm('Delete this document?'))return;
  await deleteFile(id);
  await db.ref(`${FB.docs}/${id}`).remove();
  notify('Document deleted');
}

// PROJECT ACTIONS
async function addPC(pid) {
  const inp=document.getElementById('pc-inp');
  if(!inp||!inp.value.trim())return;
  const cm=projComments[pid]||[];
  cm.push({id:Date.now(),text:inp.value.trim(),by:CU.username,name:CU.name,ts:new Date().toLocaleString('en-IN')});
  await db.ref(`${FB.comments}/${pid}`).set(cm);
}
async function togPay(pid,idx) {
  const p=projects.find(x=>x.id===pid); if(!p)return;
  const payments=[...(p.payments||[])];
  const pay=payments[idx]; if(!pay)return;
  pay.status=pay.status==='Paid'?'Pending':'Paid';
  pay.date=pay.status==='Paid'?new Date().toISOString().slice(0,10):'';
  await db.ref(`${FB.projects}/${pid}/payments`).set(payments);
  notify('Payment updated');
}
async function markDel(id) {
  await db.ref(`${FB.projects}/${id}/status`).set('Delivered');
  notify('Marked as Delivered');
}
async function archProj(id) {
  await db.ref(`${FB.projects}/${id}/status`).set('Archived');
  notify('Project archived');
}
async function deleteProject(id) {
  if(!confirm('Delete project and all its tasks permanently?'))return;
  await db.ref(`${FB.projects}/${id}`).remove();
  // Delete related tasks
  const related=tasks.filter(t=>t.projectId===id);
  for(const t of related) await db.ref(`${FB.tasks}/${t.id}`).remove();
  notify('Project deleted');
  navigate('projects');
}

// USER ACTIONS
async function togUser(un) {
  const u=USERS[un]; if(!u)return;
  await db.ref(`${FB.users}/${un}/enabled`).set(u.enabled===false?true:false);
  notify('User '+(u.enabled===false?'enabled':'disabled')+': '+un);
}
async function deleteUser(un) {
  if(!confirm(`Delete account ${un}? This cannot be undone.`))return;
  await db.ref(`${FB.users}/${un}`).remove();
  notify('Account deleted: '+un);
}

// ARCH NOTE ACTIONS
async function delNote(id) {
  if(!confirm('Delete this note?'))return;
  await db.ref(`${FB.archNotes}/${id}`).remove();
  notify('Note deleted');
}

// FILE DOWNLOAD
async function downloadDoc(docId) {
  const fileData=await getFile(docId);
  if(!fileData||!fileData.dataURL){ notify('File not found in local storage','err'); return; }
  const a=document.createElement('a');
  a.href=fileData.dataURL;
  a.download=fileData.name||'download';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  notify('Downloading: '+fileData.name);
}

// ══════════════════════════════════════════════════════════
//  MODALS
// ══════════════════════════════════════════════════════════
function showModal(title,body,wide) {
  $('modal-root').innerHTML=`
  <div class="overlay" onclick="if(event.target===this)closeM()">
    <div class="mbox${wide?' mbox-wide':''}">
      <div class="drag-handle"></div>
      <div class="mhead"><div class="mtitle">${title}</div><button class="mclose" onclick="closeM()">×</button></div>
      ${body}
    </div>
  </div>`;
}
function closeM(){$('modal-root').innerHTML='';}

// ── UPLOAD ZONE ───────────────────────────────────────────
function initUploadZone(zoneId,inputId) {
  const zone=document.getElementById(zoneId), input=document.getElementById(inputId);
  if(!zone||!input)return;
  zone.addEventListener('click',()=>input.click());
  zone.addEventListener('dragover',e=>{e.preventDefault();zone.classList.add('drag');});
  zone.addEventListener('dragleave',()=>zone.classList.remove('drag'));
  zone.addEventListener('drop',e=>{e.preventDefault();zone.classList.remove('drag');const f=e.dataTransfer.files[0];if(f)handleFileSelect(f);});
  input.addEventListener('change',()=>{if(input.files[0])handleFileSelect(input.files[0]);});
}
function handleFileSelect(file) {
  uploadedFile=file;
  const ext=file.name.split('.').pop().toLowerCase();
  const zone=document.getElementById('upload-zone');
  const preview=document.getElementById('upload-preview');
  const typeSelect=document.getElementById('df-t');
  const sizeField=document.getElementById('df-s');
  const nameField=document.getElementById('df-n');
  if(zone)zone.style.display='none';
  if(preview){preview.style.display='flex';preview.querySelector('.upload-preview-name').textContent=file.name;preview.querySelector('.upload-preview-size').textContent=fmtSize(file.size);preview.querySelector('.upload-preview-icon').textContent=fi(ext);}
  if(typeSelect)typeSelect.value=ext;
  if(sizeField)sizeField.value=fmtSize(file.size);
  if(nameField&&!nameField.value)nameField.value=file.name;
}
function clearUploadFile() {
  uploadedFile=null;
  const zone=document.getElementById('upload-zone');
  const preview=document.getElementById('upload-preview');
  const inp=document.getElementById('file-input-real');
  if(zone)zone.style.display='';
  if(preview)preview.style.display='none';
  if(inp)inp.value='';
}

// ── CREATE PROJECT ────────────────────────────────────────
function mCreateProj(){
  const team=Object.entries(USERS).filter(([,u])=>u.role==='team'&&u.enabled!==false);
  selMembers=[];
  showModal('Create New Project',`
  <form onsubmit="submitProj(event)">
    <div class="field"><label class="inp-label">Project Title *</label><input class="inp-sm" id="pf-t" required placeholder="e.g. Smart Irrigation System"></div>
    <div class="g2" style="gap:12px;">
      <div class="field"><label class="inp-label">Type *</label><input class="inp-sm" id="pf-ty" required placeholder="IoT & Embedded"></div>
      <div class="field"><label class="inp-label">Branch *</label><input class="inp-sm" id="pf-br" required placeholder="Electronics"></div>
      <div class="field"><label class="inp-label">Year</label><input class="inp-sm" id="pf-yr" value="${new Date().getFullYear()}"></div>
      <div class="field"><label class="inp-label">Deadline *</label><input class="inp-sm" id="pf-dl" type="date" required></div>
      <div class="field"><label class="inp-label">Budget (₹) *</label><input class="inp-sm" id="pf-bg" type="number" placeholder="85000" required></div>
      <div class="field"><label class="inp-label">Cost (₹)</label><input class="inp-sm" id="pf-ct" type="number" placeholder="0" value="0"></div>
    </div>
    <div class="field"><label class="inp-label">Description</label><textarea class="inp-sm" id="pf-ds" rows="2" style="resize:vertical;"></textarea></div>
    <div class="field"><label class="inp-label">Requirements</label><textarea class="inp-sm" id="pf-rq" rows="2" style="resize:vertical;"></textarea></div>
    <div class="field">
      <label class="inp-label">Assign Team Members</label>
      <div id="mchips" style="display:flex;flex-wrap:wrap;margin-top:6px;">
        ${team.map(([un,u])=>`<span class="mchip" id="ch-${un}" onclick="togChip('${un}')">${av(u.avatar,20,u.color||'#1565c0')} ${u.name.split(' ')[0]}</span>`).join('')}
      </div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:6px;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p">Create Project</button>
    </div>
  </form>`,true);
}
function togChip(un){
  const ch=document.getElementById('ch-'+un);
  if(selMembers.includes(un)){selMembers=selMembers.filter(x=>x!==un);ch.classList.remove('sel');}
  else{selMembers.push(un);ch.classList.add('sel');}
}
async function submitProj(e) {
  e.preventDefault();
  const id=gid('PRJ');
  const budget=Number(document.getElementById('pf-bg').value);
  const cost=Number(document.getElementById('pf-ct').value)||0;
  const proj={
    id, title:$('pf-t').value, type:$('pf-ty').value, branch:$('pf-br').value,
    year:$('pf-yr').value, deadline:$('pf-dl').value, budget, status:'Created',
    assignedMembers:[...selMembers], description:$('pf-ds').value,
    requirements:$('pf-rq').value, createdAt:new Date().toISOString().slice(0,10),
    payments:[], revenue:budget, cost
  };
  await db.ref(`${FB.projects}/${id}`).set(proj);
  selMembers=[];closeM();notify('Project created: '+id);
}

// ── EDIT PROJECT ──────────────────────────────────────────
function mEditProject(pid) {
  const p=projects.find(x=>x.id===pid); if(!p)return;
  const team=Object.entries(USERS).filter(([,u])=>u.role==='team'&&u.enabled!==false);
  selMembers=[...(p.assignedMembers||[])];
  showModal('Edit Project',`
  <form onsubmit="submitEditProj(event,'${pid}')">
    <div class="field"><label class="inp-label">Title</label><input class="inp-sm" id="ep-t" value="${p.title||''}"></div>
    <div class="g2" style="gap:12px;">
      <div class="field"><label class="inp-label">Type</label><input class="inp-sm" id="ep-ty" value="${p.type||''}"></div>
      <div class="field"><label class="inp-label">Branch</label><input class="inp-sm" id="ep-br" value="${p.branch||''}"></div>
      <div class="field"><label class="inp-label">Deadline</label><input class="inp-sm" id="ep-dl" type="date" value="${p.deadline||''}"></div>
      <div class="field"><label class="inp-label">Budget (₹)</label><input class="inp-sm" id="ep-bg" type="number" value="${p.budget||0}"></div>
      <div class="field"><label class="inp-label">Revenue (₹)</label><input class="inp-sm" id="ep-rv" type="number" value="${p.revenue||0}"></div>
      <div class="field"><label class="inp-label">Cost (₹)</label><input class="inp-sm" id="ep-ct" type="number" value="${p.cost||0}"></div>
    </div>
    <div class="field"><label class="inp-label">Description</label><textarea class="inp-sm" id="ep-ds" rows="2">${p.description||''}</textarea></div>
    <div class="field"><label class="inp-label">Requirements</label><textarea class="inp-sm" id="ep-rq" rows="2">${p.requirements||''}</textarea></div>
    <div class="field">
      <label class="inp-label">Team Members</label>
      <div id="mchips" style="display:flex;flex-wrap:wrap;margin-top:6px;">
        ${team.map(([un,u])=>`<span class="mchip${selMembers.includes(un)?' sel':''}" id="ch-${un}" onclick="togChip('${un}')">${av(u.avatar,20,u.color||'#1565c0')} ${u.name.split(' ')[0]}</span>`).join('')}
      </div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:6px;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p">Save Changes</button>
    </div>
  </form>`,true);
}
async function submitEditProj(e,pid) {
  e.preventDefault();
  const updates={
    title:$('ep-t').value, type:$('ep-ty').value, branch:$('ep-br').value,
    deadline:$('ep-dl').value, budget:Number($('ep-bg').value),
    revenue:Number($('ep-rv').value), cost:Number($('ep-ct').value),
    description:$('ep-ds').value, requirements:$('ep-rq').value,
    assignedMembers:[...selMembers]
  };
  await db.ref(`${FB.projects}/${pid}`).update(updates);
  selMembers=[];closeM();notify('Project updated');
}

// ── STATUS CHANGE ─────────────────────────────────────────
function mStatusChange(){
  const p=selProj;
  showModal('Change Project Status',`
  <div style="display:flex;flex-direction:column;gap:7px;">
    ${['Created','Approved','In Development','Review','Delivered','Archived'].map(s=>`
    <button onclick="doSC('${s}')" style="display:flex;align-items:center;gap:10px;padding:13px 14px;background:${p.status===s?'rgba(21,96,192,.2)':'var(--bg4)'};border:1px solid ${p.status===s?'var(--blue2)':'var(--border)'};border-radius:9px;color:${p.status===s?'var(--blue3)':'var(--text2)'};font-size:14px;text-align:left;min-height:50px;">
      <span style="width:10px;height:10px;border-radius:50%;background:${SC[s]};display:inline-block;flex-shrink:0;"></span>${s}
      ${p.status===s?'<span style="margin-left:auto;font-size:10px;font-family:var(--fm);color:var(--blue3);">Current</span>':''}
    </button>`).join('')}
  </div>`);
}
async function doSC(s) {
  if(selProj){
    await db.ref(`${FB.projects}/${selProj.id}/status`).set(s);
    selProj.status=s;
  }
  closeM();notify('Status: '+s);
}

// ── CREATE TASK ───────────────────────────────────────────
function mCreateTask(pid){
  const p=projects.find(x=>x.id===pid);
  const el=Object.entries(USERS).filter(([un])=>(p?.assignedMembers||[]).includes(un));
  showModal('Add Task',`
  <form onsubmit="submitTask(event,'${pid}')">
    <div class="field"><label class="inp-label">Task Title *</label><input class="inp-sm" id="tf-t" required placeholder="e.g. PCB Design"></div>
    <div class="field"><label class="inp-label">Assign To *</label>
      <select class="inp-sm" id="tf-a" required>
        <option value="">Select member</option>
        ${el.map(([un,u])=>`<option value="${un}">${u.name} (${u.domain})</option>`).join('')}
        ${isCEO()?`<option value="${CU.username}">${CU.name} (CEO)</option>`:''}
      </select>
    </div>
    <div class="field"><label class="inp-label">Deadline *</label><input class="inp-sm" id="tf-d" type="date" required></div>
    <div class="field"><label class="inp-label">Description</label><textarea class="inp-sm" id="tf-ds" rows="2" placeholder="Optional details…"></textarea></div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p">Create Task</button>
    </div>
  </form>`);
}
async function submitTask(e,pid) {
  e.preventDefault();
  const a=$('tf-a').value;
  const u=USERS[a];
  const id=gid('TSK');
  const task={
    id, projectId:pid, title:$('tf-t').value, assignedTo:a, domain:u?.domain||'',
    deadline:$('tf-d').value, status:'Not Started', progress:0, notes:[],
    description:$('tf-ds').value||'', createdAt:new Date().toISOString().slice(0,10)
  };
  await db.ref(`${FB.tasks}/${id}`).set(task);
  closeM();notify('Task created: '+id);
}

// ── UPLOAD DOCUMENT ───────────────────────────────────────
function mUploadDoc(pid){
  uploadedFile=null;
  const mpList=isCEO()?projects:projects.filter(p=>(p.assignedMembers||[]).includes(CU.username));
  const pt=pid?tasks.filter(t=>t.projectId===pid):[];
  const defVis=isCEO()?'ceo-only':'team-only';
  showModal('Upload Document',`
  <form onsubmit="submitDoc(event)">
    ${!pid?`<div class="field"><label class="inp-label">Project *</label>
      <select class="inp-sm" id="df-p" required onchange="updDocTasks(this.value)">
        <option value="">Select project</option>
        ${mpList.map(p=>`<option value="${p.id}">${p.id} — ${p.title}</option>`).join('')}
      </select></div>`:`<input type="hidden" id="df-p" value="${pid}">`}
    <div class="field">
      <label class="inp-label">Upload File</label>
      <div class="upload-zone" id="upload-zone"><span class="upload-zone-icon">📁</span><div class="upload-zone-title">Tap to browse or drag & drop</div><div class="upload-zone-sub">PDF, Word, Excel, Images, ZIP, DWG and more</div></div>
      <div class="upload-preview" id="upload-preview" style="display:none;"><span class="upload-preview-icon">📄</span><div><div class="upload-preview-name">filename.pdf</div><div class="upload-preview-size">—</div></div><button type="button" class="upload-preview-rm" onclick="clearUploadFile()">×</button></div>
      <input type="file" id="file-input-real" class="file-input-hidden" accept="*/*">
    </div>
    <div class="field"><label class="inp-label">Document Name *</label><input class="inp-sm" id="df-n" required placeholder="Report_v1.pdf"></div>
    <div class="g2" style="gap:12px;">
      <div class="field"><label class="inp-label">File Type</label>
        <select class="inp-sm" id="df-t">${['pdf','docx','xlsx','png','jpg','dwg','zip','mp4','txt','pptx'].map(t=>`<option value="${t}">${t.toUpperCase()}</option>`).join('')}</select>
      </div>
      <div class="field"><label class="inp-label">File Size</label><input class="inp-sm" id="df-s" placeholder="Auto-detected" value="—"></div>
    </div>
    <div class="field"><label class="inp-label">Link to Task (optional)</label>
      <select class="inp-sm" id="df-tk">
        <option value="">No task link</option>
        ${pt.map(t=>`<option value="${t.id}">${t.id} · ${t.title}</option>`).join('')}
      </select>
    </div>
    <div class="field">
      <label class="inp-label">Visibility</label>
      <div class="vis-row" style="margin-top:7px;">
        ${(isCEO()?['ceo-only','team-only','shared']:['team-only','shared']).map(v=>{const vc=VC[v];return`<button type="button" class="vbtn" id="vb-${v}" onclick="selVis('${v}')" style="${v===defVis?`background:${vc.c}1a;border-color:${vc.c};color:${vc.c};`:''}">${vc.i} ${vc.l}</button>`;}).join('')}
      </div>
      <input type="hidden" id="df-v" value="${defVis}">
    </div>
    <div id="upload-progress" style="display:none;margin-bottom:12px;">
      <div style="font-size:11px;color:var(--text4);font-family:var(--fm);margin-bottom:6px;">Saving file…</div>
      <div class="pbar-wrap"><div class="pbar" id="prog-bar" style="width:0%;background:var(--blue2);transition:width .3s;"></div></div>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p" id="submit-doc-btn">Upload Document</button>
    </div>
  </form>`,true);
  setTimeout(()=>initUploadZone('upload-zone','file-input-real'),50);
}

function updDocTasks(pid){
  const sel=document.getElementById('df-tk'); if(!sel)return;
  const pt=tasks.filter(t=>t.projectId===pid);
  sel.innerHTML='<option value="">No task link</option>'+pt.map(t=>`<option value="${t.id}">${t.id} · ${t.title}</option>`).join('');
}
function selVis(v){
  $('df-v').value=v;
  ['ceo-only','team-only','shared'].forEach(x=>{const b=document.getElementById('vb-'+x);if(!b)return;const vc=VC[x];if(x===v){b.style.background=vc.c+'1a';b.style.borderColor=vc.c;b.style.color=vc.c;}else{b.style.background='';b.style.borderColor='var(--border2)';b.style.color='var(--text4)';}});
}

async function submitDoc(e) {
  e.preventDefault();
  const pid=$('df-p').value; if(!pid){notify('Select a project','err');return;}
  const id=gid('DOC');
  const name=$('df-n').value;
  const type=$('df-t').value;
  const size=$('df-s').value;
  const taskId=$('df-tk').value||null;
  const vis=$('df-v').value;
  const prog=$('upload-progress'), progBar=$('prog-bar'), submitBtn=$('submit-doc-btn');
  if(submitBtn)submitBtn.disabled=true;
  let hasFile=false;
  if(uploadedFile){
    if(prog)prog.style.display='block';
    if(progBar)progBar.style.width='30%';
    try {
      const dataURL=await readFileAsDataURL(uploadedFile);
      if(progBar)progBar.style.width='80%';
      await saveFile(id,{id,name:uploadedFile.name,dataURL,mimeType:uploadedFile.type,size:uploadedFile.size});
      if(progBar)progBar.style.width='100%';
      hasFile=true;
    } catch(err){notify('File save failed. Metadata saved only.','err');}
  }
  const ext=uploadedFile?uploadedFile.name.split('.').pop().toLowerCase():type;
  const finalSize=uploadedFile?fmtSize(uploadedFile.size):size;
  const docObj={
    id,projectId:pid,taskId,
    name:name||(uploadedFile?uploadedFile.name:'Document'),
    uploadedBy:CU.username,role:CU.role,visibility:vis,version:1,
    timestamp:new Date().toLocaleString('en-IN'),
    size:finalSize,type:ext,locked:false,approved:false,comments:[],hasFile
  };
  await db.ref(`${FB.docs}/${id}`).set(docObj);
  closeM();uploadedFile=null;notify(hasFile?'File saved!':'Document entry added');
}
function readFileAsDataURL(file){ return new Promise((res,rej)=>{ const r=new FileReader();r.onload=e=>res(e.target.result);r.onerror=rej;r.readAsDataURL(file); }); }

// ── ADD PAYMENT ───────────────────────────────────────────
function mAddPayment(pid){
  showModal('Add Payment Stage',`
  <form onsubmit="submitPay(event,'${pid}')">
    <div class="field"><label class="inp-label">Stage Name *</label><input class="inp-sm" id="pay-n" required placeholder="e.g. Milestone 2"></div>
    <div class="field"><label class="inp-label">Amount (₹) *</label><input class="inp-sm" id="pay-a" type="number" required placeholder="30000"></div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p">Add Stage</button>
    </div>
  </form>`);
}
async function submitPay(e,pid) {
  e.preventDefault();
  const p=projects.find(x=>x.id===pid); if(!p)return;
  const payments=[...(p.payments||[]),{stage:$('pay-n').value,amount:Number($('pay-a').value),status:'Pending',date:''}];
  await db.ref(`${FB.projects}/${pid}/payments`).set(payments);
  closeM();notify('Payment stage added');
}

// ── CREATE USER ───────────────────────────────────────────
function mCreateUser(){
  showModal('Create User Account',`
  <form onsubmit="submitUser(event)">
    <div class="g2" style="gap:12px;">
      <div class="field"><label class="inp-label">First Name *</label><input class="inp-sm" id="uf-f" required autocapitalize="words"></div>
      <div class="field"><label class="inp-label">Last Name</label><input class="inp-sm" id="uf-l" autocapitalize="words"></div>
    </div>
    <div class="field"><label class="inp-label">Domain / Role *</label><input class="inp-sm" id="uf-d" required placeholder="Electronics Assembly & Testing"></div>
    <div class="field"><label class="inp-label">Username *</label><input class="inp-sm" id="uf-u" required placeholder="manoj.elec" autocapitalize="none"></div>
    <div class="field"><label class="inp-label">Password *</label><input class="inp-sm" id="uf-p" required placeholder="Strong preset password" type="password"></div>
    <div style="background:var(--bg4);border:1px solid var(--border);border-radius:9px;padding:12px 13px;margin-bottom:14px;font-size:12px;color:var(--text4);">💡 This password will be given privately to the team member.</div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button type="button" class="btn-s" onclick="closeM()">Cancel</button>
      <button type="submit" class="btn-p">Create Account</button>
    </div>
  </form>`);
}
async function submitUser(e) {
  e.preventDefault();
  const f=$('uf-f').value,l=$('uf-l').value,un=$('uf-u').value.trim().toLowerCase();
  if(USERS[un]){notify('Username already exists','err');return;}
  const initials=(f[0]+(l?l[0]:f[1]||'')).toUpperCase();
  const colors=['#1565c0','#00695c','#6a1b9a','#c2185b','#e65100','#1976d2','#4a148c','#006064'];
  const color=colors[Math.floor(Math.random()*colors.length)];
  const newUser={name:f+(l?' '+l:''),role:'team',domain:$('uf-d').value,avatar:initials,color,password:$('uf-p').value,enabled:true};
  await db.ref(`${FB.users}/${un}`).set(newUser);
  closeM();notify('Account created: '+un);
}

// ── EDIT USER ─────────────────────────────────────────────
function mEditUser(un){
  const u=USERS[un];
  showModal(`Edit — ${un}`,`
  <div class="field"><label class="inp-label">Full Name</label><input class="inp-sm" id="eu-n" value="${u.name}" autocapitalize="words"></div>
  <div class="field"><label class="inp-label">Domain / Role</label><input class="inp-sm" id="eu-d" value="${u.domain}"></div>
  <div class="field"><label class="inp-label">Password</label><input class="inp-sm" id="eu-p" value="${u.password}" type="password"></div>
  <div style="display:flex;gap:10px;justify-content:flex-end;">
    <button class="btn-s" onclick="closeM()">Cancel</button>
    <button class="btn-p" onclick="submitEdit('${un}')">Save Changes</button>
  </div>`);
}
async function submitEdit(un) {
  const n=$('eu-n').value;
  const updates={name:n,domain:$('eu-d').value,password:$('eu-p').value,avatar:n.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()};
  await db.ref(`${FB.users}/${un}`).update(updates);
  closeM();notify('User updated: '+un);
}

// ── ARCHITECTURE NOTES ────────────────────────────────────
function mNewNote(){
  showModal('New Architecture Note',`
  <div class="field"><label class="inp-label">Title *</label><input class="inp-sm" id="an-t" required></div>
  <div class="field"><label class="inp-label">Content</label><textarea class="inp-sm" id="an-c" rows="7" style="resize:vertical;font-family:var(--fm);font-size:13px;line-height:1.7;"></textarea></div>
  <div style="display:flex;gap:10px;justify-content:flex-end;">
    <button class="btn-s" onclick="closeM()">Cancel</button>
    <button class="btn-p" onclick="submitNote()">Add Note</button>
  </div>`,true);
}
async function submitNote() {
  const t=$('an-t')?.value; const c=$('an-c')?.value;
  if(!t)return;
  const id=gid('NOTE');
  await db.ref(`${FB.archNotes}/${id}`).set({id,title:t,content:c||'',editedBy:CU.username,ts:new Date().toISOString().slice(0,10),order:Date.now()});
  closeM();notify('Note added');
}
function mEditNote(id){
  const n=archNotes.find(x=>x.id===id); if(!n)return;
  showModal('Edit: '+n.title,`
  <div class="field"><label class="inp-label">Title</label><input class="inp-sm" id="en-t" value="${n.title||''}"></div>
  <div class="field"><label class="inp-label">Content</label><textarea class="inp-sm" id="en-c" rows="9" style="resize:vertical;font-family:var(--fm);font-size:13px;line-height:1.7;">${n.content||''}</textarea></div>
  <div style="display:flex;gap:10px;justify-content:flex-end;">
    <button class="btn-s" onclick="closeM()">Cancel</button>
    <button class="btn-p" onclick="submitEditNote('${id}')">Save</button>
  </div>`,true);
}
async function submitEditNote(id) {
  const updates={title:$('en-t').value,content:$('en-c').value,editedBy:CU.username,ts:new Date().toISOString().slice(0,10)};
  await db.ref(`${FB.archNotes}/${id}`).update(updates);
  closeM();notify('Note updated');
}

// ── MISC ──────────────────────────────────────────────────
window.addEventListener('resize',()=>{
  const mb=$('menu-btn'); if(!mb)return;
  mb.style.display=window.innerWidth<=768?'flex':'none';
});

document.getElementById('l-pass').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
document.getElementById('l-user').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('l-pass').focus();});

// ══════════════════════════════════════════════════════════
//  STARTUP
// ══════════════════════════════════════════════════════════
(async function startup() {
  // 1. Init Firebase
  initFirebase();

  // 2. Open IndexedDB for files
  await openIDB().catch(e=>console.warn('IDB unavailable:',e));

  // 3. Seed default users if Firebase is empty
  await ensureUsersSeeded();

  // 4. Set topbar date
  $('tb-date').textContent=new Date().toLocaleDateString('en-IN',{weekday:'short',day:'2-digit',month:'short',year:'numeric'});

  // 5. Try to restore existing session
  const savedUser=await validateSession();
  if (savedUser) {
    // Re-fetch user from Firebase
    const snap=await db.ref(`${FB.users}/${savedUser}`).once('value');
    const u=snap.val();
    if (u&&u.enabled!==false) {
      CU={username:savedUser,...u};
      _rememberMe=!!localStorage.getItem(SEC.REMEMBER_KEY);
      attachListeners();
      startPresence();
      startInactivityWatch();
      showScreen('s-welcome');
      buildWelcome();
      setTimeout(()=>enterApp(),1200);
      return;
    } else {
      clearSession();
    }
  }
  showScreen('s-login');
})();
