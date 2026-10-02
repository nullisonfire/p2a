const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff"
};

function allowedOrigins(env) {
  return new Set((env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean));
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extra }
  });
}

function cors(request, response, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return response;
  const origins=allowedOrigins(env);
  const allowed = origins.size === 0 || origins.has(origin);
  if (!allowed) return new Response("CORS origin denied", { status: 403 });
  const h = new Headers(response.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Credentials", "true");
  h.set("Vary", "Origin");
  return new Response(response.body, { status: response.status, headers: h });
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}
function b64url(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function unb64url(s) {
  s=s.replace(/-/g,"+").replace(/_/g,"/");
  while(s.length%4)s+="=";
  const raw=atob(s); return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", await sha256(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign","verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function makeSession(payload, secret) {
  const body=b64url(new TextEncoder().encode(JSON.stringify({...payload, exp: Math.floor(Date.now()/1000)+86400})));
  return body+"."+b64url(await hmac(body,secret));
}
async function readSession(request, env) {
  const cookies=request.headers.get("Cookie")||"";
  const m=cookies.match(/(?:^|;\s*)p2a_session=([^;]+)/);
  if(!m) return null;
  try {
    const [body,sig]=m[1].split(".");
    const expected=await hmac(body,env.SESSION_SECRET);
    const got=unb64url(sig);
    if(expected.length!==got.length) return null;
    let diff=0; for(let i=0;i<expected.length;i++) diff|=expected[i]^got[i];
    if(diff!==0) return null;
    const payload=JSON.parse(new TextDecoder().decode(unb64url(body)));
    if(!payload.exp || payload.exp < Date.now()/1000) return null;
    return payload;
  } catch { return null; }
}
function sessionCookie(value, maxAge=86400) {
  return `p2a_session=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=None`;
}
function clearCookie() {
  return "p2a_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None";
}
function parseAccounts(env) {
  try {
    const v=JSON.parse(env.AUTH_ACCOUNTS_JSON||"{}");
    return v && typeof v==="object" ? v : {};
  } catch { return {}; }
}
function safeSlug(v) {
  return typeof v==="string" && /^[A-Za-z0-9_-]+$/.test(v) ? v : null;
}
function getAccount(request, env, session) {
  const accounts=parseAccounts(env);
  const requested = new URL(request.url).searchParams.get("account");
  const account = requested || session?.account || Object.keys(accounts)[0];
  return account && accounts[account] ? accounts[account] : null;
}
function upstreamHeaders(auth, extra={}) {
  return {
    "Accept":"*/*",
    "Authorization":auth.authorization,
    "X-App-Key":auth.x_app_key,
    "X-Secret-Token":auth.x_secret,
    "Referer":"https://p2a.academy/",
    "User-Agent":"Mozilla/5.0",
    "Cookie":`csrftoken=${auth.csrf};token=${auth.token}`,
    ...extra
  };
}
async function upstreamJSON(url, auth, init={}) {
  const res=await fetch(url,{
    ...init,
    headers:{...upstreamHeaders(auth, init.headers||{})},
    redirect:"follow"
  });
  const text=await res.text();
  let data; try{data=JSON.parse(text)}catch{data={raw:text}};
  return {res,data};
}
async function r2Json(env,key) {
  const obj=await env.CACHE_BUCKET.get(key);
  if(!obj) return null;
  try{return await obj.json()}catch{return null}
}
async function putR2Json(env,key,data) {
  await env.CACHE_BUCKET.put(key, JSON.stringify(data), {
    httpMetadata:{contentType:"application/json; charset=utf-8", cacheControl:"private, max-age=300"}
  });
}
function accessDenied(data) {
  const s=JSON.stringify(data||"");
  return /authentication credentials were not provided|permission denied|not authenticated|access denied/i.test(s);
}

async function decryptAES(value, secret) {
  if(typeof value!=="string" || !value.trim()) return value;
  try {
    const raw=Uint8Array.from(atob(value),c=>c.charCodeAt(0));
    if(raw.length<16) return value;
    const iv=raw.slice(0,16), ciphertext=raw.slice(16);
    const keyBytes=await sha256(secret);
    const key=await crypto.subtle.importKey("raw",keyBytes,{name:"AES-CBC"},false,["decrypt"]);
    const plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-CBC",iv},key,ciphertext));
    let end=plain.length;
    const pad=plain[plain.length-1];
    if(pad>0&&pad<=16&&pad<=plain.length){
      let ok=true; for(let i=1;i<=pad;i++) if(plain[plain.length-i]!==pad) ok=false;
      if(ok) end-=pad;
    }
    return new TextDecoder("utf-8",{fatal:false}).decode(plain.slice(0,end)).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,"");
  } catch { return value; }
}
function unwrapUpstreamData(data) {
  if (data && typeof data === "object" && !Array.isArray(data) &&
      Object.prototype.hasOwnProperty.call(data, "data") &&
      data.data && typeof data.data === "object") {
    return data.data;
  }
  return data;
}

function normalizeExamPayload(raw) {
  const source = unwrapUpstreamData(raw);
  if (!source || typeof source !== "object") return source;

  // The P2A exam response stores the actual MCQs at:
  // question.body.sections[].questions[]. The original PHP flattened
  // that collection into the public `question` array.
  if (Array.isArray(source.question)) return source;

  const nested = source.question?.body?.sections;
  const questions = Array.isArray(nested)
    ? nested.flatMap(section => Array.isArray(section?.questions) ? section.questions : [])
    : [];

  return { ...source, question: questions };
}

async function decryptExam(data, secret) {
  const copy=normalizeExamPayload(data);
  if(!copy || !Array.isArray(copy.question)) return copy;
  if(!secret) throw new Error("P2A_AES_SECRET is not configured");
  for(const q of copy.question){
    if(!q||typeof q!=="object") continue;
    if("answer" in q) q.answer=await decryptAES(q.answer,secret);
    if("explanation" in q) q.explanation=await decryptAES(q.explanation,secret);
  }
  return copy;
}

function normalizeWrittenPayload(raw) {
  let source = unwrapUpstreamData(raw);
  // Some cached/API responses are wrapped more than once.
  while (source && typeof source === "object" && source.data && typeof source.data === "object" && !Array.isArray(source.levels)) {
    source = source.data;
  }
  return source;
}

async function requireSession(request,env) {
  const s=await readSession(request,env);
  if(!s) return null;
  return s;
}



function collectNodesByType(value, wanted, out=[]) {
  if (!value || typeof value !== "object") return out;
  if (!Array.isArray(value) && String(value.type || "").toLowerCase() === wanted && value.slug) {
    out.push({ slug: String(value.slug).split("/").pop(), title: value.title || value.slug });
  }
  if (Array.isArray(value)) for (const v of value) collectNodesByType(v, wanted, out);
  else for (const v of Object.values(value)) collectNodesByType(v, wanted, out);
  return out;
}
function collectContentSlugs(value, out=[]) {
  if (!value || typeof value !== "object") return out;
  if (Array.isArray(value)) { for (const v of value) collectContentSlugs(v,out); return out; }
  if (Array.isArray(value.contents)) {
    for (const c of value.contents) if (c && c.slug) out.push(String(c.slug).split("/").pop());
  }
  for (const v of Object.values(value)) collectContentSlugs(v,out);
  return out;
}
function uniqueItems(items) {
  const m=new Map(); for(const x of items) if(x?.slug) m.set(x.slug,x); return [...m.values()];
}
async function streamCacheEvents(request, env, auth, slug, type) {
  const encoder=new TextEncoder();
  const stream=new ReadableStream({
    async start(controller) {
      const send=(event,payload={})=>controller.enqueue(encoder.encode(`data: ${JSON.stringify({event,...payload})}\n\n`));
      try {
        send("status",{message:`Fetching course for ${type}...`});
        const courseRes=await upstreamJSON(`https://p2a.academy/api/course/${encodeURIComponent(slug)}`,auth);
        if(!courseRes.res.ok){ send("error",{message:`Failed to fetch course. Upstream HTTP ${courseRes.res.status}`}); controller.close(); return; }
        const course=courseRes.data;
        await putR2Json(env,`courses/${slug}.json`,course);
        const source=unwrapUpstreamData(course);
        let items=[];
        if(type==="content") items=collectContentSlugs(source).map(slug=>({slug,title:slug}));
        if(type==="pdf") items=uniqueItems(collectNodesByType(source,"pdf"));
        if(type==="exam") items=uniqueItems(collectNodesByType(source,"exam"));
        if(type==="written_exam") items=uniqueItems(collectNodesByType(source,"written_exam"));

        if(type==="exam" || type==="written_exam") {
          const resolved=[];
          for(const item of items){
            const cached=await r2Json(env,`contents/${item.slug}.json`);
            const c=unwrapUpstreamData(cached||{});
            const id=type==="exam" ? c?.exam?.id : c?.written_exam?.id;
            if(id) resolved.push({id:Number(id),slug:item.slug,title:item.title});
            else send("progress",{type,slug:item.slug,title:item.title,status:"missing_content"});
          }
          const dedupe=new Map(); for(const x of resolved) dedupe.set(x.id,x); items=[...dedupe.values()];
        }

        const threads=type==="pdf"||type==="written_exam"?10:20;
        let downloaded=0, skipped=0, failed=0;
        const total=items.length;
        send("start",{type,total,threads});
        const batches=[];
        for(let i=0;i<items.length;i+=threads) batches.push(items.slice(i,i+threads));
        for(const batch of batches){
          await Promise.all(batch.map(async item=>{
            const key= type==="content"?`contents/${item.slug}.json`: type==="pdf"?`pdf/${item.slug}.pdf`:type==="exam"?`exam/${item.id}.json`:`written/${item.id}.json`;
            const existing=await env.CACHE_BUCKET.head(key);
            if(existing){ skipped++; send("progress",{type,...(item.id?{id:item.id}:{}),slug:item.slug,title:item.title,status:"skipped",downloaded,skipped,failed,total}); return; }
            let ok=false,lastStatus=0;
            for(let attempt=0;attempt<4;attempt++){
              if(attempt) send("retry",{type,...(item.id?{id:item.id}:{}),slug:item.slug,attempt});
              try{
                const endpoint= type==="content"?`https://p2a.academy/api/content/${encodeURIComponent(item.slug)}`:type==="pdf"?`https://p2a.academy/api/pdf-proxy?content=${encodeURIComponent(item.slug)}`:type==="exam"?`https://p2a.academy/api/exam/${encodeURIComponent(String(item.id))}`:`https://p2a.academy/api/practice-written-exam/${encodeURIComponent(String(item.id))}`;
                const headers= type==="pdf" ? {
                  "Accept":"application/pdf,*/*","Authorization":auth.authorization,"X-App-Key":auth.x_app_key,"X-Secret-Token":auth.x_secret,
                  "Referer":`https://p2a.academy/dashboard/my-courses/${slug}/?content=${encodeURIComponent(item.slug)}&contentType=pdf`,"Cookie":`token=${auth.token};csrftoken=${auth.csrf}`,"User-Agent":"Mozilla/5.0"
                } : undefined;
                if(type==="pdf") {
                  const pdfRes=await fetch(endpoint,{headers:headers,redirect:"follow"}); lastStatus=pdfRes.status;
                  if(pdfRes.ok){ const buf=await pdfRes.arrayBuffer(); const ct=pdfRes.headers.get("content-type")||""; if(buf.byteLength && /pdf/i.test(ct)){ await env.CACHE_BUCKET.put(key,buf,{httpMetadata:{contentType:"application/pdf",cacheControl:"private, max-age=300"}}); ok=true; } }
                } else {
                  const u=await upstreamJSON(endpoint,auth); lastStatus=u.res.status;
                  if(u.res.ok && u.data && typeof u.data==="object"){ await putR2Json(env,key,u.data); ok=true; }
                }
              }catch{}
              if(ok) break;
              if(attempt<3) await new Promise(r=>setTimeout(r,(attempt+1)*1000));
            }
            if(ok){ downloaded++; send("progress",{type,...(item.id?{id:item.id}:{}),slug:item.slug,title:item.title,status:"downloaded",downloaded,skipped,failed,total}); }
            else { failed++; send("progress",{type,...(item.id?{id:item.id}:{}),slug:item.slug,title:item.title,status:"failed",http_code:lastStatus,downloaded,skipped,failed,total}); }
          }));
        }
        send("complete",{type,total,downloaded,skipped,failed});
      } catch(e) { send("error",{message:e?.message||"Cache operation failed"}); }
      finally { controller.close(); }
    }
  });
  return new Response(stream,{status:200,headers:{"content-type":"text/event-stream; charset=utf-8","cache-control":"no-cache, no-transform","connection":"keep-alive","x-accel-buffering":"no"}});
}

export default {
  async fetch(request, env) {
    if(request.method==="OPTIONS"){
      return cors(request,new Response(null,{status:204,headers:{
        "Access-Control-Allow-Methods":"GET,POST,OPTIONS",
        "Access-Control-Allow-Headers":"Content-Type",
        "Access-Control-Max-Age":"86400"
      }}),env);
    }
    const url=new URL(request.url);
    let response;
    try {
      if(url.pathname==="/api/health") response=json({ok:true});
      else if(url.pathname==="/api/auth/login" && request.method==="POST"){
        const body=await request.json().catch(()=>({}));
        if(!env.ACCESS_PASSCODE || String(body.passcode||"")!==String(env.ACCESS_PASSCODE)) return cors(request,json({error:"Incorrect passcode."},401),env);
        const accounts=parseAccounts(env), account=body.account && accounts[body.account] ? body.account : Object.keys(accounts)[0] || null;
        const token=await makeSession({account},env.SESSION_SECRET);
        response=new Response(JSON.stringify({success:true,account}),{status:200,headers:{...JSON_HEADERS,"Set-Cookie":sessionCookie(token)}});
      } else if(url.pathname==="/api/auth/session"){
        const s=await readSession(request,env);
        response=s?json({authenticated:true,account:s.account}):json({authenticated:false},401);
      } else if(url.pathname==="/api/auth/accounts"){
        const s=await requireSession(request,env); if(!s) return cors(request,json({error:"Authentication required"},401),env);
        response=json({accounts:Object.keys(parseAccounts(env))});
      } else if(url.pathname==="/api/auth/select-account" && request.method==="POST"){
        const s=await requireSession(request,env); if(!s) return cors(request,json({error:"Authentication required"},401),env);
        const body=await request.json().catch(()=>({})), accounts=parseAccounts(env);
        if(!accounts[body.account]) return cors(request,json({error:"Unknown account"},400),env);
        const token=await makeSession({...s,account:body.account},env.SESSION_SECRET);
        response=new Response(JSON.stringify({success:true,account:body.account}),{headers:{...JSON_HEADERS,"Set-Cookie":sessionCookie(token)}});
      } else if(url.pathname==="/api/auth/logout"){
        response=new Response(JSON.stringify({success:true}),{headers:{...JSON_HEADERS,"Set-Cookie":clearCookie()}});
      } else {
        const s=await requireSession(request,env);
        if(!s) return cors(request,json({error:"Authentication required"},401),env);
        const auth=getAccount(request,env,s);
        if(!auth) return cors(request,json({error:"No API account configured"},500),env);

        if(url.pathname==="/api/courses"){
          const obj=await env.CACHE_BUCKET.get("catalog/courses.json");
          if(obj) response=new Response(await obj.arrayBuffer(),{headers:{"content-type":"application/json; charset=utf-8","cache-control":"private, max-age=300"}});
          else {
            // The archive contains a static catalog; deploy it to R2 as catalog/courses.json.
            response=json({error:"Course catalog missing from R2"},503);
          }
        } else if(url.pathname==="/api/purchased-courses"){
          const data=await r2Json(env,"state/purchased_course.json") || {};
          response=json(data);
        } else if(url.pathname==="/api/cache/slugs"){
          const listed=await env.CACHE_BUCKET.list({prefix:"courses/",limit:1000});
          response=json({slugs:listed.objects.map(o=>o.key.slice("courses/".length).replace(/\.json$/,"" )).filter(Boolean).sort((a,b)=>a.localeCompare(b))});
        } else if(url.pathname==="/api/cache/sse"){
          const slug=safeSlug(url.searchParams.get("slug")||"");
          const type=String(url.searchParams.get("type")||"content").toLowerCase();
          if(!slug) response=json({error:"Missing or invalid course slug"},400);
          else if(!["content","pdf","exam","written_exam"].includes(type)) response=json({error:"Invalid type"},400);
          else response=await streamCacheEvents(request,env,auth,slug,type);
        } else if(url.pathname==="/api/fetch"){
          const type=url.searchParams.get("fetch");
          const bypass=url.searchParams.get("bypass_cache")==="1";
          if(type==="course"){
            const slug=safeSlug(url.searchParams.get("course_url")?.match(/\/courses\/([A-Za-z0-9_-]+)/)?.[1] || "");
            if(!slug) response=json({error:"Invalid course URL"},400);
            else {
              const cachedRaw=await r2Json(env,`courses/${slug}.json`);
              const cached=cachedRaw ? unwrapUpstreamData(cachedRaw) : null;
              if(cached && !bypass) response=json({data:cached,source:"cache"});
              else {
                const u=await upstreamJSON(`https://p2a.academy/api/course/${encodeURIComponent(slug)}`,auth);
                if(u.res.status>=400) response=json({error:`Upstream returned HTTP ${u.res.status}`},502);
                else {const data=unwrapUpstreamData(u.data); await putR2Json(env,`courses/${slug}.json`,data); response=json({data,source:"api"});}
              }
            }
          } else if(type==="content"){
            const slug=safeSlug(url.searchParams.get("slug")||"");
            if(!slug) response=json({error:"Invalid content slug"},400);
            else {
              const cachedRaw=!bypass?await r2Json(env,`contents/${slug}.json`):null;
              let data=cachedRaw ? unwrapUpstreamData(cachedRaw) : null;
              if(!data){
                const u=await upstreamJSON(`https://p2a.academy/api/content/${encodeURIComponent(slug)}`,auth);
                if(u.res.status>=400) response=json({error:u.data?.detail||`Upstream returned HTTP ${u.res.status}`},u.res.status===403?403:502);
                else {data=unwrapUpstreamData(u.data); if(!accessDenied(data)&&!bypass) await putR2Json(env,`contents/${slug}.json`,data); response=json({data,source:"api"});}
              } else response=json({data,source:"cache"});
            }
          } else response=json({error:"Invalid parameters"},400);
        } else if(url.pathname==="/api/purchase"){
          const slug=safeSlug(url.searchParams.get("slug")||"");
          if(!slug) response=json({status:"error",message:"Missing slug"},400);
          else {
            const current=await r2Json(env,"state/purchased_course.json")||{};
            if(current[slug]) response=json({status:"already_purchased",message:"This Course Was Already Purchased",slug,purchased_at:current[slug]?.purchased_at||null});
            else {
              const p=await upstreamJSON(`https://p2a.academy/api/payment/${encodeURIComponent(slug)}?format=json`,auth);
              if(p.res.status!==200 || !p.data?.price_ids?.[0]) response=json({status:"error",message:"Failed to get price_id"},502);
              else {
                const result=await upstreamJSON("https://p2a.academy/api/free-order",auth,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({price_id:p.data.price_ids[0]})});
                if(result.data?.message==="Order Stored Successfully"){
                  current[slug]={purchased_at:new Date().toISOString()};
                  await putR2Json(env,"state/purchased_course.json",current);
                  response=json({status:"success",slug,price_id:p.data.price_ids[0]});
                } else response=json({status:"failed",slug,response:result.data},400);
              }
            }
          }
        } else if(url.pathname==="/api/exam"){
          const id=url.searchParams.get("id");
          if(!/^\d+$/.test(id||"")) response=json({error:"Invalid exam ID provided"},400);
          else {
            let raw=await r2Json(env,`exam/${id}.json`);
            if(!raw){
              const u=await upstreamJSON(`https://p2a.academy/api/exam/${id}?format=json`,auth);
              if(u.res.status!==200) response=json({error:`API returned HTTP code: ${u.res.status}`},502);
              else {raw=u.data; await putR2Json(env,`exam/${id}.json`,raw);}
            }
            const normalized=await decryptExam(raw,env.P2A_AES_SECRET);
            response=json(normalized);
          }
        } else if(url.pathname==="/api/written"){
          const id=url.searchParams.get("exam");
          if(!/^\d+$/.test(id||"")) response=json({error:"Invalid exam ID"},400);
          else {
            let raw=await r2Json(env,`written/${id}.json`);
            if(!raw){
              const u=await upstreamJSON(`https://p2a.academy/api/practice-written-exam/${id}/`,auth);
              if(u.res.status!==200) response=json({error:`API returned HTTP code: ${u.res.status}`},502);
              else {raw=u.data; await putR2Json(env,`written/${id}.json`,raw);}
            }
            response=json(normalizeWrittenPayload(raw));
          }
        } else if(url.pathname==="/api/profile"){
          const [p,c]=await Promise.all([
            upstreamJSON("https://p2a.academy/api/user-profile",auth),
            upstreamJSON("https://p2a.academy/api/authenticated-courses",auth)
          ]);
          response=json({success:true,profile:p.data?.data||p.data,courses:c.data});
        } else if(url.pathname==="/api/pdf"){
          const slug=safeSlug(url.searchParams.get("slug")||"");
          if(!slug) response=json({error:"Invalid PDF slug"},400);
          else {
            const obj=await env.CACHE_BUCKET.get(`pdf/${slug}.pdf`);
            if(obj) response=new Response(obj.body,{headers:{"content-type":"application/pdf","content-disposition":`inline; filename="${slug}.pdf"`,"cache-control":"private, max-age=86400","x-content-type-options":"nosniff"}});
            else {
              const u=await fetch(`https://p2a.academy/api/pdf-proxy?content=${encodeURIComponent(slug)}`,{headers:{"Accept":"application/pdf,*/*","Cookie":`token=${auth.token}`,"User-Agent":"P2A-Cloudflare-Worker/1.0"}});
              if(!u.ok) response=new Response("PDF request failed",{status:u.status});
              else {
                if (!u.body) throw new Error("Upstream PDF body missing");
                const [cacheStream, responseStream] = u.body.tee();
                await env.CACHE_BUCKET.put(`pdf/${slug}.pdf`, cacheStream, {httpMetadata:{contentType:"application/pdf",cacheControl:"private, max-age=86400"}});
                response=new Response(responseStream,{headers:{"content-type":u.headers.get("content-type")||"application/pdf","content-disposition":`inline; filename="${slug}.pdf"`,"cache-control":"private, max-age=86400"}});
              }
            }
          }
        } else {
          response=json({error:"Not found"},404);
        }
      }
    } catch(e) {
      response=json({error:e?.message||"Internal server error"},500);
    }
    return cors(request,response,env);
  }
};
