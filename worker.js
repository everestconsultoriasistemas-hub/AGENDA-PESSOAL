// Cloudflare Worker: roda a cada minuto, lê a agenda no Firestore e envia Web Push.
const b64u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'=')),c=>c.charCodeAt(0));
const enc=new TextEncoder();
const cat=(...a)=>{const o=new Uint8Array(a.reduce((n,x)=>n+x.length,0));let p=0;for(const x of a){o.set(x,p);p+=x.length}return o};
async function hkdf(salt,ikm,info,len){
  const k=await crypto.subtle.importKey('raw',ikm,'HKDF',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt,info},k,len*8));
}
async function encrypt(sub,text){ // RFC 8291 (aes128gcm)
  const ua=unb64u(sub.keys.p256dh),auth=unb64u(sub.keys.auth);
  const kp=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const asPub=new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey));
  const uaKey=await crypto.subtle.importKey('raw',ua,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const ecdh=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:uaKey},kp.privateKey,256));
  const ikm=await hkdf(auth,ecdh,cat(enc.encode('WebPush: info\0'),ua,asPub),32);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const cek=await hkdf(salt,ikm,enc.encode('Content-Encoding: aes128gcm\0'),16);
  const nonce=await hkdf(salt,ikm,enc.encode('Content-Encoding: nonce\0'),12);
  const key=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['encrypt']);
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},key,cat(enc.encode(text),new Uint8Array([2]))));
  return cat(salt,new Uint8Array([0,0,16,0]),new Uint8Array([65]),asPub,ct);
}
async function vapid(env,endpoint){
  const pub=unb64u(env.VAPID_PUBLIC);
  const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64u(pub.slice(1,33)),y:b64u(pub.slice(33,65)),d:env.VAPID_PRIVATE,ext:true},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const h=b64u(enc.encode(JSON.stringify({typ:'JWT',alg:'ES256'})));
  const c=b64u(enc.encode(JSON.stringify({aud:new URL(endpoint).origin,exp:Math.floor(Date.now()/1000)+43200,sub:'mailto:'+(env.CONTACT||'agenda@example.com')})));
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,enc.encode(h+'.'+c));
  return 'vapid t='+h+'.'+c+'.'+b64u(sig)+', k='+env.VAPID_PUBLIC;
}
async function send(env,sub,payload){
  const r=await fetch(sub.endpoint,{method:'POST',headers:{Authorization:await vapid(env,sub.endpoint),'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream',TTL:'900',Urgency:'high'},body:await encrypt(sub,JSON.stringify(payload))});
  return r.status;
}
async function run(env,code){
  const base='https://firestore.googleapis.com/v1/projects/'+env.FIREBASE_PROJECT+'/databases/(default)/documents/agendas/'+code;
  const r=await fetch(base+'?key='+env.FIREBASE_API_KEY);if(!r.ok)return;
  const f=(await r.json()).fields||{};
  const items=f.data?(JSON.parse(f.data.stringValue).items||[]):[];
  let subs=f.subs?JSON.parse(f.subs.stringValue):[];
  if(!subs.length)return;
  const now=Date.now(),off=env.TZ_OFFSET||'-03:00',dead=new Set();
  for(const it of items){
    if(it.done||!it.time)continue;
    const diff=(Date.parse(it.date+'T'+it.time+':00'+off)-now)/60000;
    let kind=null,body='';
    if(!it.pre&&diff<=15&&diff>0){kind='pre';body='Começa em '+Math.ceil(diff)+' min ('+it.time+')'}
    else if(!it.now&&diff<=0&&diff>-120){kind='now';body=(it.type==='meeting'?'Reunião':'Tarefa')+' agora ('+it.time+')'}
    if(!kind)continue;
    const key=code+'|'+it.id+'|'+it.date+'|'+it.time+'|'+kind;
    if(await env.SENT.get(key))continue;
    await env.SENT.put(key,'1',{expirationTtl:86400});
    for(const s of subs){
      try{const st=await send(env,s,{title:it.title,body,tag:String(it.id)+kind});if(st===404||st===410)dead.add(s.endpoint)}catch(e){}
    }
  }
  if(dead.size){
    subs=subs.filter(s=>!dead.has(s.endpoint));
    await fetch(base+'?updateMask.fieldPaths=subs&key='+env.FIREBASE_API_KEY,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({fields:{subs:{stringValue:JSON.stringify(subs)}}})});
  }
}
export default{async scheduled(ev,env,ctx){
  // AGENDA_CODE aceita um ou vários códigos separados por vírgula: codigo1,codigo2,codigo3
  const codes=(env.AGENDA_CODE||'').split(',').map(c=>c.trim()).filter(Boolean);
  ctx.waitUntil(Promise.all(codes.map(c=>run(env,c).catch(()=>{}))));
}};
