const ORIGIN = "https://linguib.github.io";
const PROJECT_ID = "dr-bassants-office-hours";
const TEACHER_UID = "RTK8C8IBRTPhunubJyxAygg1mVn2";
const enc = new TextEncoder();
const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")), c=>c.charCodeAt(0));
const concat = (...parts) => { const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0)); let i=0; for(const p of parts){out.set(p,i);i+=p.length;} return out; };
function cors(extra={}) { return {"Access-Control-Allow-Origin":ORIGIN,"Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization",...extra}; }
function json(data,status=200){return new Response(JSON.stringify(data),{status,headers:{...cors(),"Content-Type":"application/json","Cache-Control":"no-store"}})}
async function sha(text){return b64u(await crypto.subtle.digest("SHA-256",enc.encode(text)));}
async function verifyTeacher(request){
  const h=request.headers.get("Authorization")||""; if(!h.startsWith("Bearer ")) return false;
  const token=h.slice(7); const p=token.split("."); if(p.length!==3)return false;
  try{
    const header=JSON.parse(new TextDecoder().decode(unb64u(p[0])));
    const claims=JSON.parse(new TextDecoder().decode(unb64u(p[1])));
    if(header.alg!=="RS256"||!header.kid||claims.aud!==PROJECT_ID||claims.iss!==`https://securetoken.google.com/${PROJECT_ID}`||claims.sub!==TEACHER_UID||claims.sub.length>128||claims.exp<=Date.now()/1000||claims.iat>Date.now()/1000+60)return false;
    const cacheKey=new Request("https://local.invalid/firebase-jwks");
    let jwks=await caches.default.match(cacheKey);
    if(jwks)jwks=await jwks.json(); else {
      const r=await fetch("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com");
      if(!r.ok)return false; jwks=await r.json();
      await caches.default.put(cacheKey,new Response(JSON.stringify(jwks),{headers:{"Cache-Control":"public, max-age=3600"}}));
    }
    const jwk=jwks.keys.find(k=>k.kid===header.kid); if(!jwk)return false;
    const key=await crypto.subtle.importKey("jwk",jwk,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,unb64u(p[2]),enc.encode(p[0]+"."+p[1]));
  }catch(e){console.error("Teacher token validation failed",e);return false;}
}
async function hkdf(salt,ikm,info,bytes){const key=await crypto.subtle.importKey("raw",ikm,"HKDF",false,["deriveBits"]);return new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt,info},key,bytes*8));}
async function vapidAuth(endpoint,env){
  const pub=unb64u(env.VAPID_PUBLIC_KEY); if(pub.length!==65||pub[0]!==4)throw new Error("Invalid VAPID public key format");
  const key=await crypto.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:b64u(pub.slice(1,33)),y:b64u(pub.slice(33)),d:env.VAPID_PRIVATE_KEY},{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  const claims={aud:new URL(endpoint).origin,exp:Math.floor(Date.now()/1000)+12*60*60,sub:env.VAPID_SUBJECT};
  const unsigned=b64u(enc.encode(JSON.stringify({typ:"JWT",alg:"ES256"})))+"."+b64u(enc.encode(JSON.stringify(claims)));
  const sig=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,enc.encode(unsigned));
  return `vapid t=${unsigned}.${b64u(sig)}, k=${env.VAPID_PUBLIC_KEY}`;
}
async function encryptPayload(text,sub){
  const ua=unb64u(sub.keys.p256dh), auth=unb64u(sub.keys.auth), salt=crypto.getRandomValues(new Uint8Array(16));
  const as=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  const asPub=new Uint8Array(await crypto.subtle.exportKey("raw",as.publicKey));
  const uaKey=await crypto.subtle.importKey("raw",ua,{name:"ECDH",namedCurve:"P-256"},false,[]);
  const shared=new Uint8Array(await crypto.subtle.deriveBits({name:"ECDH",public:uaKey},as.privateKey,256));
  const ikm=await hkdf(auth,shared,concat(enc.encode("WebPush: info\0"),ua,asPub),32);
  const cek=await hkdf(salt,ikm,enc.encode("Content-Encoding: aes128gcm\0"),16);
  const nonce=await hkdf(salt,ikm,enc.encode("Content-Encoding: nonce\0"),12);
  const aes=await crypto.subtle.importKey("raw",cek,"AES-GCM",false,["encrypt"]);
  const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce},aes,concat(enc.encode(text),new Uint8Array([2])));
  const header=new Uint8Array(86); header.set(salt,0); new DataView(header.buffer).setUint32(16,4096); header[20]=65; header.set(asPub,21);
  return concat(header,new Uint8Array(cipher));
}
async function sendPush(sub,message,env){
  const headers={Authorization:await vapidAuth(sub.endpoint,env),TTL:"86400",Urgency:"high","Content-Encoding":"aes128gcm","Content-Type":"application/octet-stream"};
  const body=await encryptPayload(JSON.stringify(message),sub);
  return fetch(sub.endpoint,{method:"POST",headers,body});
}
async function siteverify(token,request,env){
  const r=await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({secret:env.TURNSTILE_SECRET_KEY,response:token,remoteip:request.headers.get("CF-Connecting-IP")||undefined})});
  if(!r.ok)return false; const v=await r.json(); return v.success===true&&v.hostname==="linguib.github.io"&&v.action==="student_message";
}
export default { async fetch(request,env){
  const url=new URL(request.url);
  if(request.method==="OPTIONS")return new Response(null,{status:204,headers:cors()});
  if(request.headers.get("Origin")!==ORIGIN)return json({error:"Origin not allowed"},403);
  if(url.pathname==="/push/key"&&request.method==="GET")return new Response(env.VAPID_PUBLIC_KEY,{headers:{...cors(),"Content-Type":"text/plain","Cache-Control":"public,max-age=3600"}});
  if(url.pathname==="/push/subscribe"&&request.method==="POST"){
    if(!(await verifyTeacher(request)))return json({error:"Teacher authentication required"},401);
    let sub; try{sub=await request.json()}catch{return json({error:"Invalid JSON"},400)}
    if(!sub||typeof sub.endpoint!=="string"||!sub.endpoint.startsWith("https://")||!sub.keys?.p256dh||!sub.keys?.auth)return json({error:"Invalid subscription"},400);
    const id=await sha(sub.endpoint); await env.PWA_SUBS.put("sub:"+id,JSON.stringify(sub)); return json({ok:true});
  }
  if(url.pathname==="/push/unsubscribe"&&request.method==="POST"){
    if(!(await verifyTeacher(request)))return json({error:"Teacher authentication required"},401);
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400)}
    if(typeof body.endpoint!=="string")return json({error:"Endpoint required"},400);
    await env.PWA_SUBS.delete("sub:"+await sha(body.endpoint));return json({ok:true});
  }
  if(url.pathname==="/notify"&&request.method==="POST"){
    let body;try{body=await request.json()}catch{return json({error:"Invalid JSON"},400)}
    if(typeof body.token!=="string"||body.token.length>2048)return json({error:"Turnstile token required"},400);
    if(!(await siteverify(body.token,request,env)))return json({error:"Turnstile verification failed"},403);
    const ip=request.headers.get("CF-Connecting-IP")||"unknown"; const rateKey="rate:"+await sha(ip); const last=Number(await env.PWA_SUBS.get(rateKey)||0);
    if(Date.now()-last<10000)return json({ok:true,throttled:true});
    await env.PWA_SUBS.put(rateKey,String(Date.now()),{expirationTtl:60});
    const listed=await env.PWA_SUBS.list({prefix:"sub:"}); let sent=0,removed=0,failed=0;
    for(const item of listed.keys){
      const raw=await env.PWA_SUBS.get(item.name); if(!raw)continue;
      try{const sub=JSON.parse(raw);const res=await sendPush(sub,{title:"New student message",body:"A student has sent you a message. Open your teacher inbox to view it.",url:ORIGIN+"/Bassant-Khaled-s-Office-Hours/#teacher"},env);
        if(res.status===404||res.status===410){await env.PWA_SUBS.delete(item.name);removed++;}
        else if(res.ok)sent++; else {failed++;console.error("Push service response",res.status,await res.text());}
      }catch(e){failed++;console.error("Push send failed",e)}
    }
    return json({ok:true,sent,removed,failed});
  }
  return json({error:"Not found"},404);
}};
