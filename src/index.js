// 回覧板サイト(複数グループ対応)Cloudflare Workers + KV
// 見る画面: /g/グループID  載せる画面: /g/グループID/post  グループ登録: /new
const MAX = 10 * 1024 * 1024, KEEP = 100;
const TYPES = { pdf: "application/pdf", jpg: "image/jpeg", png: "image/png", doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
const LABEL = { pdf: "PDF", jpg: "写真", png: "写真", doc: "Word", docx: "Word" };
const SLUG = "[a-z0-9-]{2,30}";
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8" } });
const sha = async s => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, "0")).join("");
const today = () => { const d = new Date(Date.now() + 9 * 36e5); return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月${d.getUTCDate()}日`; };
const CSS = `:root{--bg:#F6F3EC;--ink:#1E1E1E;--s:#4A4A4A;--card:#fff;--g:#1F6F4A;--line:#C9C2B2;--err:#B3261E}
@media(prefers-color-scheme:dark){:root{--bg:#1B1D1B;--ink:#F2F2F2;--s:#CFCFCF;--card:#262926;--g:#3FA877;--line:#4B504B;--err:#FF8A80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:22px/1.7 "BIZ UDPGothic","Hiragino Sans","Yu Gothic UI",Meiryo,sans-serif}
main{max-width:640px;margin:0 auto;padding:24px 16px 60px}h1{font-size:32px;margin:0 0 16px}
.c{background:var(--card);border:2px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px}
.t{font-weight:bold;word-break:break-all}.d{color:var(--s);font-size:18px}img{max-width:100%;border-radius:10px;margin-top:8px}
a.b,button,input{font:inherit}a.b,button{display:block;width:100%;text-align:center;text-decoration:none;font-weight:bold;font-size:24px;padding:16px;border-radius:14px;border:0;background:var(--g);color:#fff;cursor:pointer;margin-top:10px}
button.r{background:none;border:2px solid var(--err);color:var(--err);font-size:18px;padding:8px}button:disabled{opacity:.5}
input{width:100%;padding:12px;border:2px solid var(--line);border-radius:12px;background:var(--bg);color:var(--ink);margin:6px 0 14px}
#m{font-weight:bold;margin-top:12px;word-break:break-all}`;
const page = (title, body, script = "") => new Response(`<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main>${script ? `<script>${script}</script>` : ""}</body></html>`,
  { headers: { "content-type": "text/html; charset=utf-8" } });
const notFound = () => page("見つかりません", `<h1>見つかりません</h1><div class="c">アドレスが違うようです。</div>`);

function detect(b) {
  const s = (...a) => a.every((v, i) => b[i] === v);
  return s(0x25, 0x50, 0x44, 0x46) ? "pdf" : s(0xff, 0xd8, 0xff) ? "jpg" : s(0x89, 0x50, 0x4e, 0x47) ? "png"
    : s(0xd0, 0xcf, 0x11, 0xe0) ? "doc" : s(0x50, 0x4b, 0x03, 0x04) ? "docx" : null;
}
const hmac = async (k, m) => {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(k), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(m)))].map(b => b.toString(16).padStart(2, "0")).join("");
};
// ログイン中か確認(クッキー)。OKならグループ情報、だめならnull
async function session(req, env, slug) {
  const t = (/(?:^|; )s=([^;]+)/.exec(req.headers.get("cookie") || "") || [])[1];
  const [sl, exp, sig] = (t || "").split(".");
  if (!sig || sl !== slug || !(+exp > Date.now()) || !env.ADMIN_PASS) return null;
  const g = await env.FILES.get("g:" + slug, "json");
  return g && sig === await hmac(env.ADMIN_PASS + g.h, sl + "." + exp) ? g : null;
}
const needLogin = () => json({ ok: false, message: "ログインし直してください。" }, 401);

// ---- 見る画面(誰でも見られる) ----
async function view(slug, env) {
  const g = await env.FILES.get("g:" + slug, "json");
  if (!g) return notFound();
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  const items = idx.map(x => `<div class="c"><div class="d">${esc(x.d)}</div><div class="t">${esc(x.t)}</div>`
    + (/jpg|png/.test(x.n) ? `<a href="/f/${x.n}"><img loading="lazy" src="/f/${x.n}" alt="${esc(x.t)}"></a>` : "")
    + `<a class="b" href="/f/${x.n}">${LABEL[x.n.split(".")[1]]}を開く</a></div>`).join("") || `<div class="c">まだ回覧はありません。</div>`;
  return page(g.name + "の回覧板", `<h1>${esc(g.name)}の回覧板</h1>${items}`);
}

// ---- 載せる画面 ----
async function postPage(slug, env, ok, req) {
  const g = await session(req, env, slug);
  if (!g) return Response.redirect(new URL(req.url).origin + "/login?g=" + slug, 302);
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  const list = idx.map(x => `<div class="c"><div class="d">${esc(x.d)}</div><div class="t">${esc(x.t)}</div><button class="r" data-id="${x.n}">この回覧を削除</button></div>`).join("");
  const body = `<h1>${esc(g.name)}<br>回覧を載せる</h1><div class="c">
<button id="pick" type="button" style="background:none;color:var(--g);border:3px solid var(--g)">ファイル・写真を選ぶ</button>
<input id="file" type="file" multiple hidden accept="image/*,application/pdf,.pdf,.doc,.docx">
<div id="fn" class="t">まだ選んでいません</div>
<label>題名(書かなくても大丈夫です)</label><input id="title" maxlength="100">
<button id="send" type="button">載せる</button><div id="m" style="color:var(--g)">${ok ? "載せました。" : ""}</div></div>
<button class="r" id="out" type="button" style="margin-bottom:24px">ログアウト</button><h1 style="font-size:26px">載せたもの</h1>${list || `<div class="c">まだありません。</div>`}`;
  return page("回覧を載せる", body, String.raw`
const $=i=>document.getElementById(i),S="${slug}";
const msg=(t,ok)=>{$("m").textContent=t;$("m").style.color=ok?"var(--g)":"var(--err)"};
$("pick").onclick=()=>$("file").click();
$("out").onclick=async()=>{await fetch("/api/logout",{method:"POST"});location.href="/login?g="+S};
$("file").onchange=()=>{$("fn").textContent=[...$("file").files].map(f=>f.name).join("、")||"まだ選んでいません"};
async function shrink(f){if(!f.type.startsWith("image/"))return f;try{const b=await createImageBitmap(f),s=Math.min(1,2000/Math.max(b.width,b.height)),c=document.createElement("canvas");c.width=Math.round(b.width*s);c.height=Math.round(b.height*s);const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.drawImage(b,0,0,c.width,c.height);return await new Promise(r=>c.toBlob(r,"image/jpeg",.85))}catch(e){return f}}
$("send").onclick=async()=>{
const fs=[...$("file").files];if(!fs.length)return msg("先にファイルを選んでください。");
$("send").disabled=true;
try{for(let i=0;i<fs.length;i++){msg("送っています… ("+(i+1)+"/"+fs.length+")",true);
const fd=new FormData();fd.append("title",$("title").value||fs[i].name.replace(/\.[^.]*$/,""));fd.append("file",await shrink(fs[i]),fs[i].name);
const r=await fetch("/api/post/"+S,{method:"POST",body:fd}),d=await r.json().catch(()=>({}));
if(!r.ok||!d.ok)throw new Error(d.message||"うまく載せられませんでした。")}
location.href=location.pathname+"?ok=1"}catch(e){msg(e.message)}finally{$("send").disabled=false}};
document.querySelectorAll("button.r").forEach(b=>b.onclick=async()=>{
if(!confirm("この回覧を削除します。よろしいですか?"))return;
const r=await fetch("/api/del/"+S,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:b.dataset.id})}),d=await r.json().catch(()=>({}));
if(r.ok&&d.ok)location.href=location.pathname;else msg(d.message||"削除できませんでした。")});`);
}

async function apiPost(slug, req, env) {
  if (!await session(req, env, slug)) return needLogin();
  const fd = await req.formData();
  const file = fd.get("file");
  if (!file || typeof file === "string") return json({ ok: false, message: "ファイルがありません。" }, 400);
  if (file.size > MAX) return json({ ok: false, message: "ファイルが大きすぎます(1つ10MBまで)。" }, 413);
  const buf = await file.arrayBuffer(), ext = detect(new Uint8Array(buf.slice(0, 8)));
  if (!ext) return json({ ok: false, message: "このファイルは載せられません。PDF・写真・Wordを選んでください。" }, 400);
  const n = crypto.randomUUID().replaceAll("-", "") + "." + ext;
  await env.FILES.put("f:" + n, buf);
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  idx.unshift({ n, t: String(fd.get("title") || "回覧板").trim().slice(0, 100) || "回覧板", d: today() });
  const old = idx.splice(KEEP);
  await env.FILES.put("i:" + slug, JSON.stringify(idx));
  await Promise.all(old.map(x => env.FILES.delete("f:" + x.n)));
  return json({ ok: true });
}
async function apiDel(slug, req, env) {
  if (!await session(req, env, slug)) return needLogin();
  const b = await req.json().catch(() => ({}));
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  if (idx.some(x => x.n === b.id)) {
    await env.FILES.delete("f:" + b.id);
    await env.FILES.put("i:" + slug, JSON.stringify(idx.filter(x => x.n !== b.id)));
  }
  return json({ ok: true });
}
async function file(n, env) {
  const ext = n.split(".")[1];
  if (!TYPES[ext]) return notFound();
  const body = await env.FILES.get("f:" + n, { type: "stream" });
  if (!body) return notFound();
  const h = { "content-type": TYPES[ext], "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" };
  if (ext.startsWith("doc")) h["content-disposition"] = `attachment; filename="kairan.${ext}"`;
  return new Response(body, { headers: h });
}

// ---- 5回続けて間違えるとロック(回線ごと。15分→30分→60分と延びる) ----
const ipKey = req => { const ip = req.headers.get("cf-connecting-ip") || "?"; return ip.includes(":") ? ip.split(":").slice(0, 4).join(":") : ip; };
const fmt = m => m >= 60 ? Math.ceil(m / 60) + "時間" : m + "分";
const waitOf = l => l && l.until > Date.now() ? Math.ceil((l.until - Date.now()) / 6e4) : 0;
const lockMsg = m => `続けて間違えたため、ロックされています。あと${fmt(m)}ほどたってから、もう一度ためしてください。`;
async function miss(env, key, l, what) {
  const n = ((l && l.n) || 0) + 1, until = n % 5 ? (l && l.until) || 0 : Date.now() + Math.min(15 * 2 ** (n / 5 - 1), 60) * 6e4;
  await env.FILES.put(key, JSON.stringify({ n, until }), { expirationTtl: 86400 });
  const w = waitOf({ until });
  return w ? json({ ok: false, message: lockMsg(w) }, 429)
    : json({ ok: false, message: `${what}が違います。(あと${5 - n % 5}回間違えると、しばらく使えなくなります)` }, 403);
}

// ---- ログイン ----
const loginPage = g => page("ログイン", `<h1>ログイン</h1><div class="c">
<label>グループID</label><input id="sl" value="${esc(g)}" autocomplete="username">
<label>合言葉</label><input id="pw" type="password" autocomplete="current-password">
<button id="go" type="button">ログイン</button><div id="m" style="color:var(--err)"></div></div>`, String.raw`
const $=i=>document.getElementById(i);
$("go").onclick=async()=>{const r=await fetch("/api/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({slug:$("sl").value.trim(),pw:$("pw").value})}),d=await r.json().catch(()=>({}));
if(r.ok&&d.ok)location.href="/g/"+d.slug+"/post";else $("m").textContent=d.message||"ログインできませんでした。"};`);
async function apiLogin(req, env) {
  const b = await req.json().catch(() => ({})), slug = String(b.slug || "");
  const g = new RegExp(`^${SLUG}$`).test(slug) && env.ADMIN_PASS ? await env.FILES.get("g:" + slug, "json") : null;
  if (!g) return json({ ok: false, message: "グループIDか合言葉が違います。" }, 403);
  const lk = "l:" + slug + ":" + ipKey(req), l = await env.FILES.get(lk, "json"), w = waitOf(l);
  if (w) return json({ ok: false, message: lockMsg(w) }, 429);
  if (g.h !== await sha(slug + ":" + String(b.pw || ""))) return miss(env, lk, l, "グループIDか合言葉");
  if (l) await env.FILES.delete(lk);
  const exp = Date.now() + 30 * 864e5;
  return new Response(JSON.stringify({ ok: true, slug }), { headers: { "content-type": "application/json; charset=utf-8",
    "set-cookie": `s=${slug}.${exp}.${await hmac(env.ADMIN_PASS + g.h, slug + "." + exp)}; Path=/; Max-Age=${30 * 86400}; HttpOnly; Secure; SameSite=Lax` } });
}
const apiLogout = () => new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": "s=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" } });

// ---- グループ登録(管理用の合言葉が必要) ----
const newPage = () => page("グループを登録", `<h1>グループを登録</h1><div class="c">
<label>管理用の合言葉</label><input id="ad" type="password">
<label>グループID(半角の小文字英数字とハイフン、2〜30文字)</label><input id="sl" placeholder="例: 1-1">
<label>グループの名前</label><input id="nm" maxlength="40" placeholder="例: 1条1丁目">
<label>載せる人用の合言葉(半角の小文字英数字4文字以上)</label><input id="pw">
<button id="go" type="button">登録する</button><div id="m"></div></div>`, String.raw`
const $=i=>document.getElementById(i);
$("go").onclick=async()=>{const r=await fetch("/api/new",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({admin:$("ad").value,slug:$("sl").value.trim(),name:$("nm").value.trim(),pw:$("pw").value})}),d=await r.json().catch(()=>({}));
const m=$("m"),ok=r.ok&&d.ok;m.style.color=ok?"var(--g)":"var(--err)";m.textContent="";
if(ok){const u=location.origin+"/g/"+d.slug;m.append("登録しました。");
[["見る画面",u],["載せる画面",u+"/post"]].forEach(([n,h])=>{const p=document.createElement("div"),a=document.createElement("a");a.href=h;a.target="_blank";a.textContent=h;a.style.color="var(--g)";p.append(n+": ",a);m.append(p)})}
else m.textContent=d.message||"登録できませんでした。"};`);
async function apiNew(req, env) {
  const b = await req.json().catch(() => ({}));
  const lk = "l:~admin:" + ipKey(req), l = await env.FILES.get(lk, "json"), w = waitOf(l);
  if (w) return json({ ok: false, message: lockMsg(w) }, 429);
  if (!env.ADMIN_PASS || b.admin !== env.ADMIN_PASS) return miss(env, lk, l, "管理用の合言葉");
  if (l) await env.FILES.delete(lk);
  if (!new RegExp(`^${SLUG}$`).test(b.slug || "")) return json({ ok: false, message: "グループIDは半角の小文字英数字とハイフンで、2〜30文字にしてください。" }, 400);
  if (!b.name || b.name.length > 40 || !b.pw || b.pw.length < 4) return json({ ok: false, message: "名前と、4文字以上の合言葉を入れてください。" }, 400);
  await env.FILES.put("g:" + b.slug, JSON.stringify({ name: b.name, h: await sha(b.slug + ":" + b.pw) }));
  const ks = await env.FILES.list({ prefix: "l:" + b.slug + ":" });
  await Promise.all(ks.keys.map(k => env.FILES.delete(k.name)));
  return json({ ok: true, slug: b.slug });
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url), p = u.pathname, post = req.method === "POST";
    try {
      let r;
      if (p === "/") return page("回覧板", `<h1>回覧板</h1><div class="c">グループごとのアドレスを開いてください。</div>`);
      if (p === "/new") return newPage();
      if (p === "/login") return loginPage(u.searchParams.get("g") || "");
      if (p === "/api/login" && post) return apiLogin(req, env);
      if (p === "/api/logout" && post) return apiLogout();
      if (p === "/api/new" && post) return apiNew(req, env);
      if ((r = new RegExp(`^/g/(${SLUG})/?$`).exec(p))) return view(r[1], env);
      if ((r = new RegExp(`^/g/(${SLUG})/post/?$`).exec(p))) return postPage(r[1], env, u.searchParams.has("ok"), req);
      if (post && (r = new RegExp(`^/api/post/(${SLUG})$`).exec(p))) return apiPost(r[1], req, env);
      if (post && (r = new RegExp(`^/api/del/(${SLUG})$`).exec(p))) return apiDel(r[1], req, env);
      if ((r = /^\/f\/([0-9a-f]{32}\.[a-z]+)$/.exec(p))) return file(r[1], env);
    } catch (e) {
      console.error(e);
      return json({ ok: false, message: "うまくいきませんでした。もう一度ためしてください。" }, 500);
    }
    return notFound();
  },
};
