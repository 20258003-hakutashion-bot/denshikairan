// 回覧板サイト(複数グループ・Webプッシュ通知・既読確認対応) Cloudflare Workers + KV
// 見る画面: /g/グループID  載せる画面: /g/グループID/post  グループ登録: /new
// 必要な環境変数(Secrets): ADMIN_PASS, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY

const MAX = 10 * 1024 * 1024, KEEP = 100;
const TYPES = { pdf: "application/pdf", jpg: "image/jpeg", png: "image/png", doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" };
const LABEL = { pdf: "PDF", jpg: "写真", png: "写真", doc: "Word", docx: "Word" };
const SLUG = "[a-z0-9-]{2,30}";
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8" } });
const sha = async s => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, "0")).join("");
const jst = () => new Date(Date.now() + 9 * 36e5);
const today = () => { const d = jst(); return `${d.getUTCFullYear()}年${d.getUTCMonth() + 1}月${d.getUTCDate()}日`; };
const nowStr = () => { const d = jst(); return `${d.getUTCMonth() + 1}/${d.getUTCDate()} ${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`; };

const CSS = `:root{--bg:#F6F3EC;--ink:#1E1E1E;--s:#4A4A4A;--card:#fff;--g:#1F6F4A;--line:#C9C2B2;--err:#B3261E;--sub:#EBF3EF}
@media(prefers-color-scheme:dark){:root{--bg:#1B1D1B;--ink:#F2F2F2;--s:#CFCFCF;--card:#262926;--g:#3FA877;--line:#4B504B;--err:#FF8A80;--sub:#1E3329}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:22px/1.7 "BIZ UDPGothic","Hiragino Sans","Yu Gothic UI",Meiryo,sans-serif}
main{max-width:640px;margin:0 auto;padding:24px 16px 60px}h1{font-size:32px;margin:0 0 16px}
.c{background:var(--card);border:2px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px}
.c.notice{background:var(--sub);border-color:var(--g)}
.t{font-weight:bold;word-break:break-all}.d{color:var(--s);font-size:18px}img{max-width:100%;border-radius:10px;margin-top:8px}
a.b,button,input{font:inherit}a.b,button{display:block;width:100%;text-align:center;text-decoration:none;font-weight:bold;font-size:24px;padding:16px;border-radius:14px;border:0;background:var(--g);color:#fff;cursor:pointer;margin-top:10px}
button.outline{background:none;border:3px solid var(--g);color:var(--g)}
button.done{background:var(--sub);border:2px solid var(--g);color:var(--g);font-size:20px;padding:12px}
button.r{background:none;border:2px solid var(--err);color:var(--err);font-size:18px;padding:8px}
button.sm{font-size:18px;padding:8px 12px;width:auto;display:inline-block;margin-top:6px}
button:disabled{opacity:.5}
input{width:100%;padding:12px;border:2px solid var(--line);border-radius:12px;background:var(--bg);color:var(--ink);margin:6px 0 14px}
#m{font-weight:bold;margin-top:12px;word-break:break-all}
.readers{margin-top:12px;padding-top:10px;border-top:1px dashed var(--line);font-size:18px;color:var(--s)}
.badge{display:inline-block;background:var(--g);color:#fff;font-size:16px;padding:2px 10px;border-radius:99px;margin-right:6px}`;

const page = (title, body, script = "", headExtra = "") => new Response(`<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">${headExtra}<title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main>${script ? `<script>${script}</script>` : ""}</body></html>`,
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

// ---- Web Push 暗号化・送信処理 (RFC 8291 / Web Crypto API) ----
const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=")), c => c.charCodeAt(0));
const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const concat = (...a) => { const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let o = 0; for (const x of a) { r.set(x, o); o += x.length; } return r; };

async function sendWebPush(sub, payload, env) {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) return false;
  const pubBytes = b64uToBuf(env.VAPID_PUBLIC_KEY);
  const jwk = { kty: "EC", crv: "P-256", x: bufToB64u(pubBytes.slice(1, 33)), y: bufToB64u(pubBytes.slice(33, 65)), d: env.VAPID_PRIVATE_KEY };
  const vapidKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);

  const aud = new URL(sub.endpoint).origin;
  const enc = new TextEncoder();
  const jwtHeader = bufToB64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const jwtClaim = bufToB64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: "mailto:admin@example.com" })));
  const jwtSig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, vapidKey, enc.encode(`${jwtHeader}.${jwtClaim}`));
  const jwt = `${jwtHeader}.${jwtClaim}.${bufToB64u(jwtSig)}`;

  const clientPub = await crypto.subtle.importKey("raw", b64uToBuf(sub.keys.p256dh), { name: "ECDH", namedCurve: "P-256" }, true, []);
  const serverKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: clientPub }, serverKeys.privateKey, 256);
  const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", serverKeys.publicKey));
  const authSecret = b64uToBuf(sub.keys.auth);
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const hkdf = async (ikm, s, info, len) => {
    const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: s, info }, k, len * 8));
  };
  const prk = await hkdf(sharedSecret, authSecret, concat(enc.encode("WebPush: info\0"), b64uToBuf(sub.keys.p256dh), serverPubRaw), 32);
  const cek = await hkdf(prk, salt, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(prk, salt, enc.encode("Content-Encoding: nonce\0"), 12);

  const aesKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, concat(enc.encode(payload), new Uint8Array([2]))));
  const header = new Uint8Array(21 + serverPubRaw.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096, false);
  header[20] = serverPubRaw.length;
  header.set(serverPubRaw, 21);

  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      "TTL": "86400",
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      "Authorization": `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body: concat(header, ciphertext)
  });
  return res.status !== 404 && res.status !== 410;
}

// ---- Service Worker & Manifest ----
const swScript = () => new Response(`
self.addEventListener("push", e => {
  const d = e.data ? e.data.json() : { title: "新しい回覧板", body: "回覧板が届きました", url: "/" };
  e.waitUntil(self.registration.showNotification(d.title, { body: d.body, data: { url: d.url } }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const u = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then(cs => {
    for (const c of cs) { if (new URL(c.url).pathname === u && "focus" in c) return c.focus(); }
    return clients.openWindow(u);
  }));
});`, { headers: { "content-type": "application/javascript; charset=utf-8", "service-worker-allowed": "/" } });

async function manifest(slug, env) {
  const g = await env.FILES.get("g:" + slug, "json");
  if (!g) return notFound();
  return json({
    name: g.name + "の回覧板",
    short_name: g.name,
    start_url: "/g/" + slug,
    scope: "/g/" + slug,
    display: "standalone",
    background_color: "#F6F3EC",
    theme_color: "#1F6F4A"
  });
}

// ログイン中か確認(クッキー)
async function session(req, env, slug) {
  const t = (/(?:^|; )s=([^;]+)/.exec(req.headers.get("cookie") || "") || [])[1];
  const [sl, exp, sig] = (t || "").split(".");
  if (!sig || sl !== slug || !(+exp > Date.now()) || !env.ADMIN_PASS) return null;
  const g = await env.FILES.get("g:" + slug, "json");
  return g && sig === await hmac(env.ADMIN_PASS + g.h, sl + "." + exp) ? g : null;
}
const needLogin = () => json({ ok: false, message: "ログインし直してください。" }, 401);

// ---- 見る画面(住民用：通知登録＋「見ました」機能つき) ----
async function view(slug, env) {
  const g = await env.FILES.get("g:" + slug, "json");
  if (!g) return notFound();
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  const items = idx.map(x => `<div class="c"><div class="d">${esc(x.d)}</div><div class="t">${esc(x.t)}</div>`
    + (/jpg|png/.test(x.n) ? `<a href="/f/${x.n}"><img loading="lazy" src="/f/${x.n}" alt="${esc(x.t)}"></a>` : "")
    + `<a class="b" href="/f/${x.n}">${LABEL[x.n.split(".")[1]]}を開く</a>`
    + `<button type="button" class="outline read-btn" data-id="${x.n}">見ました（確認）</button></div>`).join("") || `<div class="c">まだ回覧はありません。</div>`;

  const topBox = `
  <div class="c notice" id="nameBox">
    <div id="nameEdit">
      <div class="t">はじめに「お名前」を入れてください</div>
      <div class="d">回覧の「見ました」ボタンを押すときに使います。</div>
      <input id="uname" maxlength="20" placeholder="例: 佐藤 一郎">
      <button type="button" id="saveName">名前を保存する</button>
    </div>
    <div id="nameShow" style="display:none">
      <div>お名前：<strong id="dispName"></strong> <button type="button" class="outline sm" id="editNameBtn">変更</button></div>
    </div>
  </div>
  <div class="c" id="pushBox" style="display:none">
    <div class="t">新しい回覧のお知らせ（通知）</div>
    <div id="pushDesc" class="d">回覧が載ったときにスマホへ通知します。</div>
    <button type="button" id="pushBtn">通知を受け取る</button>
  </div>`;

  const script = String.raw`
const $=i=>document.getElementById(i), S="${slug}", VKEY="${esc(env.VAPID_PUBLIC_KEY || "")}";
let uid = localStorage.getItem("kb_uid");
if (!uid) { uid = crypto.randomUUID(); localStorage.setItem("kb_uid", uid); }

function renderName() {
  const n = localStorage.getItem("kb_name") || "";
  if (n) { $("nameEdit").style.display="none"; $("nameShow").style.display="block"; $("dispName").textContent=n; $("uname").value=n; }
  else { $("nameEdit").style.display="block"; $("nameShow").style.display="none"; }
}
$("saveName").onclick = () => {
  const v = $("uname").value.trim();
  if (!v) return alert("お名前を入力してください。");
  localStorage.setItem("kb_name", v); renderName();
};
$("editNameBtn").onclick = () => { $("nameEdit").style.display="block"; $("nameShow").style.display="none"; };
renderName();

// 既読状況の読み込みと「見ました」ボタン
async function loadReads() {
  const r = await fetch("/api/reads/" + S + "?uid=" + encodeURIComponent(uid)).then(x => x.json()).catch(() => ({}));
  if (!r.ok) return;
  document.querySelectorAll(".read-btn").forEach(b => {
    const info = r.mine[b.dataset.id];
    if (info) {
      b.className = "done read-btn";
      b.textContent = "✓ 確認済み（" + info.name + " / " + info.at + "）";
    }
  });
}
document.querySelectorAll(".read-btn").forEach(b => b.onclick = async () => {
  let name = localStorage.getItem("kb_name") || "";
  if (!name) {
    name = prompt("「見ました」を記録するため、お名前を入力してください（例：佐藤 一郎）");
    if (!name || !name.trim()) return;
    name = name.trim().slice(0, 20);
    localStorage.setItem("kb_name", name);
    renderName();
  }
  b.disabled = true;
  const r = await fetch("/api/read/" + S, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ id: b.dataset.id, uid, name })
  }).then(x => x.json()).catch(() => ({}));
  b.disabled = false;
  if (r.ok) {
    b.className = "done read-btn";
    b.textContent = "✓ 確認済み（" + r.name + " / " + r.at + "）";
  } else alert(r.message || "記録できませんでした。");
});
loadReads();

// Webプッシュ通知の案内と登録
(async () => {
  if (!VKEY) return;
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const isStandalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  $("pushBox").style.display = "block";

  if (isIOS && !isStandalone) {
    $("pushDesc").innerHTML = "iPhoneで通知を受け取るには、画面下の<strong>「共有ボタン（□に↑）」</strong>を押して<strong>「ホーム画面に追加」</strong>をしてから開いてください。";
    $("pushBtn").style.display = "none";
    return;
  }
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    $("pushBox").style.display = "none";
    return;
  }
  const reg = await navigator.serviceWorker.register("/sw.js");
  const cur = await reg.pushManager.getSubscription();
  if (cur && Notification.permission === "granted") {
    $("pushDesc").textContent = "このスマホに新しい回覧の通知が届きます。";
    $("pushBtn").className = "done";
    $("pushBtn").textContent = "✓ 通知はオンになっています";
  }
  $("pushBtn").onclick = async () => {
    $("pushBtn").disabled = true;
    try {
      const perm = await Notification.requestPermission();
      if (perm !== "granted") { alert("通知が許可されませんでした。ブラウザの設定を確認してください。"); return; }
      const pad = "=".repeat((4 - VKEY.length % 4) % 4);
      const raw = atob((VKEY + pad).replace(/-/g, "+").replace(/_/g, "/"));
      const key = Uint8Array.from(raw, c => c.charCodeAt(0));
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      const r = await fetch("/api/sub/" + S, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sub) });
      if (r.ok) {
        $("pushDesc").textContent = "設定完了！新しい回覧が載るとお知らせが届きます。";
        $("pushBtn").className = "done";
        $("pushBtn").textContent = "✓ 通知はオンになっています";
      }
    } catch (e) { alert("通知の設定に失敗しました。"); }
    finally { $("pushBtn").disabled = false; }
  };
})();`;

  return page(g.name + "の回覧板", `<h1>${esc(g.name)}の回覧板</h1>${topBox}${items}`, script, `<link rel="manifest" href="/g/${slug}/manifest.json">`);
}

// ---- 載せる画面(役員用：誰が見たか一覧つき) ----
async function postPage(slug, env, ok, req) {
  const g = await session(req, env, slug);
  if (!g) return Response.redirect(new URL(req.url).origin + "/login?g=" + slug, 302);
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  const subs = await env.FILES.get("p:" + slug, "json") || [];
  const readsList = await Promise.all(idx.map(x => env.FILES.get(`r:${slug}:${x.n}`, "json")));

  const list = idx.map((x, i) => {
    const rs = readsList[i] || [];
    const names = rs.length
      ? rs.map(r => `${esc(r.name)}<span style="font-size:15px">(${esc(r.at)})</span>`).join("、")
      : "まだ確認した人はいません";
    return `<div class="c"><div class="d">${esc(x.d)}</div><div class="t">${esc(x.t)}</div>
      <div class="readers"><span class="badge">確認済み ${rs.length}人</span><div style="margin-top:6px">${names}</div></div>
      <button class="r" data-id="${x.n}">この回覧を削除</button></div>`;
  }).join("");

  const body = `<h1>${esc(g.name)}<br>回覧を載せる</h1><div class="c">
<div class="d" style="margin-bottom:8px">通知登録中のスマホ：<strong>${subs.length}台</strong></div>
<button id="pick" type="button" class="outline">ファイル・写真を選ぶ</button>
<input id="file" type="file" multiple hidden accept="image/*,application/pdf,.pdf,.doc,.docx">
<div id="fn" class="t">まだ選んでいません</div>
<label>題名(書かなくても大丈夫です)</label><input id="title" maxlength="100">
<button id="send" type="button">載せて通知を送る</button><div id="m" style="color:var(--g)">${ok ? "載せて、登録者に通知を送りました。" : ""}</div></div>
<button class="r" id="out" type="button" style="margin-bottom:24px">ログアウト</button><h1 style="font-size:26px">載せたもの・確認状況</h1>${list || `<div class="c">まだありません。</div>`}`;

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
if(i===fs.length-1)fd.append("notify","1");
const r=await fetch("/api/post/"+S,{method:"POST",body:fd}),d=await r.json().catch(()=>({}));
if(!r.ok||!d.ok)throw new Error(d.message||"うまく載せられませんでした。")}
location.href=location.pathname+"?ok=1"}catch(e){msg(e.message)}finally{$("send").disabled=false}};
document.querySelectorAll("button[data-id]").forEach(b=>b.onclick=async()=>{
if(!confirm("この回覧を削除します。よろしいですか?"))return;
const r=await fetch("/api/del/"+S,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:b.dataset.id})}),d=await r.json().catch(()=>({}));
if(r.ok&&d.ok)location.href=location.pathname;else msg(d.message||"削除できませんでした。")});`);
}

// ---- API: 投稿 + プッシュ通知一斉送信 ----
async function apiPost(slug, req, env) {
  const g = await session(req, env, slug);
  if (!g) return needLogin();
  const fd = await req.formData();
  const file = fd.get("file");
  if (!file || typeof file === "string") return json({ ok: false, message: "ファイルがありません。" }, 400);
  if (file.size > MAX) return json({ ok: false, message: "ファイルが大きすぎます(1つ10MBまで)。" }, 413);
  const buf = await file.arrayBuffer(), ext = detect(new Uint8Array(buf.slice(0, 8)));
  if (!ext) return json({ ok: false, message: "このファイルは載せられません。PDF・写真・Wordを選んでください。" }, 400);

  const n = crypto.randomUUID().replaceAll("-", "") + "." + ext;
  const title = String(fd.get("title") || "回覧板").trim().slice(0, 100) || "回覧板";
  await env.FILES.put("f:" + n, buf);
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  idx.unshift({ n, t: title, d: today() });
  const old = idx.splice(KEEP);
  await env.FILES.put("i:" + slug, JSON.stringify(idx));
  await Promise.all(old.flatMap(x => [env.FILES.delete("f:" + x.n), env.FILES.delete(`r:${slug}:${x.n}`)]));

  // 複数枚同時アップロード時は最後の1枚でまとめて1回通知
  if (fd.get("notify") === "1") {
    const subs = await env.FILES.get("p:" + slug, "json") || [];
    if (subs.length) {
      const payload = JSON.stringify({ title: `${g.name}の回覧板`, body: `新しい回覧「${title}」が届きました`, url: `/g/${slug}` });
      const results = await Promise.all(subs.map(s => sendWebPush(s, payload, env).catch(() => true)));
      const alive = subs.filter((_, i) => results[i]);
      if (alive.length !== subs.length) await env.FILES.put("p:" + slug, JSON.stringify(alive));
    }
  }
  return json({ ok: true });
}

// ---- API: 削除（既読記録も一緒に削除） ----
async function apiDel(slug, req, env) {
  if (!await session(req, env, slug)) return needLogin();
  const b = await req.json().catch(() => ({}));
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  if (idx.some(x => x.n === b.id)) {
    await Promise.all([
      env.FILES.delete("f:" + b.id),
      env.FILES.delete(`r:${slug}:${b.id}`),
      env.FILES.put("i:" + slug, JSON.stringify(idx.filter(x => x.n !== b.id)))
    ]);
  }
  return json({ ok: true });
}

// ---- API: 通知購読の登録 ----
async function apiSub(slug, req, env) {
  const g = await env.FILES.get("g:" + slug, "json");
  if (!g) return json({ ok: false }, 404);
  const sub = await req.json().catch(() => null);
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return json({ ok: false }, 400);
  const subs = await env.FILES.get("p:" + slug, "json") || [];
  const next = subs.filter(s => s.endpoint !== sub.endpoint);
  next.push({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
  await env.FILES.put("p:" + slug, JSON.stringify(next));
  return json({ ok: true });
}

// ---- API: 「見ました」の記録と取得 ----
async function apiRead(slug, req, env) {
  const b = await req.json().catch(() => ({}));
  const id = String(b.id || ""), uid = String(b.uid || "").slice(0, 64), name = String(b.name || "").trim().slice(0, 20);
  if (!id || !uid || !name) return json({ ok: false, message: "入力が足りません。" }, 400);
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  if (!idx.some(x => x.n === id)) return json({ ok: false, message: "回覧が見つかりません。" }, 404);

  const key = `r:${slug}:${id}`;
  const list = await env.FILES.get(key, "json") || [];
  const at = nowStr();
  const next = list.filter(x => x.uid !== uid);
  next.push({ uid, name, at });
  await env.FILES.put(key, JSON.stringify(next));
  return json({ ok: true, name, at });
}

async function apiReads(slug, uid, env) {
  const idx = await env.FILES.get("i:" + slug, "json") || [];
  const mine = {};
  if (uid) {
    const lists = await Promise.all(idx.map(x => env.FILES.get(`r:${slug}:${x.n}`, "json")));
    idx.forEach((x, i) => {
      const hit = (lists[i] || []).find(r => r.uid === uid);
      if (hit) mine[x.n] = { name: hit.name, at: hit.at };
    });
  }
  return json({ ok: true, mine });
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

// ---- ロック・ログイン・グループ登録（元のまま） ----
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
      if (p === "/sw.js") return swScript();
      if (p === "/new") return newPage();
      if (p === "/login") return loginPage(u.searchParams.get("g") || "");
      if (p === "/api/login" && post) return apiLogin(req, env);
      if (p === "/api/logout" && post) return apiLogout();
      if (p === "/api/new" && post) return apiNew(req, env);
      if ((r = new RegExp(`^/g/(${SLUG})/?$`).exec(p))) return view(r[1], env);
      if ((r = new RegExp(`^/g/(${SLUG})/manifest\\.json$`).exec(p))) return manifest(r[1], env);
      if ((r = new RegExp(`^/g/(${SLUG})/post/?$`).exec(p))) return postPage(r[1], env, u.searchParams.has("ok"), req);
      if (post && (r = new RegExp(`^/api/post/(${SLUG})$`).exec(p))) return apiPost(r[1], req, env);
      if (post && (r = new RegExp(`^/api/del/(${SLUG})$`).exec(p))) return apiDel(r[1], req, env);
      if (post && (r = new RegExp(`^/api/sub/(${SLUG})$`).exec(p))) return apiSub(r[1], req, env);
      if (post && (r = new RegExp(`^/api/read/(${SLUG})$`).exec(p))) return apiRead(r[1], req, env);
      if (!post && (r = new RegExp(`^/api/reads/(${SLUG})$`).exec(p))) return apiReads(r[1], u.searchParams.get("uid") || "", env);
      if ((r = /^\/f\/([0-9a-f]{32}\.[a-z]+)$/.exec(p))) return file(r[1], env);
    } catch (e) {
      console.error(e);
      return json({ ok: false, message: "うまくいきませんでした。もう一度ためしてください。" }, 500);
    }
    return notFound();
  },
};
