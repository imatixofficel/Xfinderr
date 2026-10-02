"use strict";
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=v=>String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));
const IC={grid:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',list:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',gear:'<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14 3h-4l-.6 2.7a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2 1.2L10 21h4l.6-2.7a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z"/>',bolt:'<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',menu:'<path d="M4 7h16M4 12h16M4 17h16"/>',search:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',refresh:'<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>'};
const fillIcons=r=>$$("svg[data-ic]",r).forEach(s=>{s.setAttribute("viewBox","0 0 24 24");s.classList.add("i");s.innerHTML=IC[s.dataset.ic]||""});
const T={fa:{god1:"به نام خدا",hello:"کاربر Xfinder",menu:"منو",system:"سیستم",dashboard:"داشبورد",configs:"کانفیگ‌ها",sources:"منابع",settings:"تنظیمات",promo:"کانفیگ‌ها <b>هر ۱۰ دقیقه</b><br>خودکار تازه می‌شوند",refresh:"بروزرسانی",welcome:"به Xfinder خوش آمدید!",updated:"آخرین بروزرسانی",qs_t:"اشتراک شخصی خودت را بساز",qs_d:"همه کانفیگ‌های سالم در یک لینک؛ در برنامه‌ات وارد کن و تمام.",qs_b:"کپی لینک اشتراک",remixed_l:"ترکیب با IP تمیز",proto_t:"پروتکل‌ها",assets:"کانفیگ‌ها",configs_d:"اول کانفیگ‌های ترکیب‌شده با IP تمیز نمایش داده می‌شوند.",wg_d:"با Cloudflare WARP و IP تمیز. فایل .conf را دانلود کن یا لینک را کپی کن.",wg_gen_t:"ساخت کانفیگ اختصاصی",wg_gen_d:"کلید در مرورگر خودت ساخته می‌شود و فقط برای تو است.",wg_gen_b:"بساز",src_d:"منابع معتبر و امتیاز اعتماد آن‌ها",lang_l:"زبان",sub_l:"لینک‌های اشتراک",copy:"کپی",copied:"کپی شد!",all:"همه",clean:"IP تمیز",server:"سرور",type:"نوع",ping:"پینگ",trust:"اعتماد",more:"نمایش بیشتر",refreshed:"بروزرسانی شد",detail:"جزئیات",download:"دانلود .conf",empty:"هنوز کانفیگی منتشر نشده. اجرای Collector را بررسی کنید.",copyall:"کپی همه",search:"جستجو",sel:"یک کانفیگ را انتخاب کن",nowg:"هنوز WireGuard ساخته نشده.",genfail:"مرورگر اجازه نداد. از کانفیگ‌های آماده استفاده کن.",genok:"کانفیگ اختصاصی ساخته شد",count:"تعداد",origin:"منبع"},
en:{god1:"In the Name of God",hello:"Xfinder User",menu:"MENU",system:"SYSTEM",dashboard:"Dashboard",configs:"Configs",sources:"Sources",settings:"Settings",promo:"Configs refresh <b>every 10 min</b><br>automatically",refresh:"Refresh",welcome:"Welcome to Xfinder!",updated:"Last update",qs_t:"Build your own subscription",qs_d:"All healthy configs in one link. Import it in your app and you're done.",qs_b:"Copy subscription link",remixed_l:"merged with clean IPs",proto_t:"Protocols",assets:"Configs",configs_d:"Configs merged with clean IPs are shown first.",wg_d:"Cloudflare WARP with clean IPs. Download the .conf or copy the link.",wg_gen_t:"Create your own config",wg_gen_d:"Keys are created in your browser and belong only to you.",wg_gen_b:"Create",src_d:"Reputable sources and their trust score",lang_l:"Language",sub_l:"Subscription links",copy:"Copy",copied:"Copied!",all:"All",clean:"Clean IP",server:"Server",type:"Type",ping:"Ping",trust:"Trust",more:"Show more",refreshed:"Refreshed",detail:"Details",download:"Download .conf",empty:"No configs yet. Check the collector run.",copyall:"Copy all",search:"Search",sel:"Select a config",nowg:"No WireGuard yet.",genfail:"Browser blocked it. Use the ready configs.",genok:"Your config is ready",count:"Count",origin:"Source"}};
let lang=localStorage.getItem("xf_lang")||((navigator.language||"").startsWith("fa")?"fa":"en");
const t=k=>T[lang][k]||k;
function applyLang(){document.documentElement.lang=lang;document.documentElement.dir=lang==="fa"?"rtl":"ltr";
 $$("[data-i]").forEach(e=>{const v=t(e.dataset.i);if(e.dataset.i==="promo")e.innerHTML=v;else e.textContent=v});
 $$("[data-ip]").forEach(e=>e.placeholder=t(e.dataset.ip));$("#lang span").textContent=lang==="fa"?"FA":"EN";localStorage.setItem("xf_lang",lang);if(D)renderAll()}
const toast=m=>{const e=$("#toast");e.textContent=m;e.classList.add("show");clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.remove("show"),1600)};
const copy=async s=>{try{await navigator.clipboard.writeText(s)}catch{const a=document.createElement("textarea");a.value=s;document.body.append(a);a.select();document.execCommand("copy");a.remove()}toast(t("copied"))};
// wordmark: هر حرف جدا انیمیت می‌شود
$$("[data-wm]").forEach(e=>{e.setAttribute("aria-label",e.dataset.wm);e.innerHTML=[...e.dataset.wm].map((c,i)=>`<span style="--n:${i}" aria-hidden="true">${c}</span>`).join("")});
fillIcons();
// data
let D=null,view=[],sel=null,filter={p:"all",q:""};
const base=location.href.replace(/[#?].*$/,"").replace(/[^/]*$/,"");
async function load(){try{const r=await fetch("data/configs.json?ts="+Date.now(),{cache:"no-store"});D=await r.json()}catch{D={stats:{},sources:{},configs:[],source_list:[]}}D.configs=D.configs||[];return D}
const pc=x=>x.protocol==="wireguard"?"WG":(x.protocol||"").toUpperCase();
const pcls=n=>n&&n<150?"g":"";
function spark(x){let h=0;const s=(x.server||"")+x.port;for(const c of s)h=(h*31+c.charCodeAt(0))>>>0;const b=Number(x.tcp_ping_ms)||200;let p="";for(let i=0;i<8;i++){h=(h*1103515245+12345)>>>0;const y=4+((h>>8)%14)*(Math.min(b,400)/400+.4);p+=(i?"L":"M")+i*12+" "+Math.min(21,y).toFixed(1)}return`<svg class="spark" viewBox="0 0 84 24"><path d="${p}"/></svg>`}
function renderBars(){const top=D.configs.filter(x=>x.tcp_ping_ms).slice(0,7);const mx=Math.max(1,...top.map(x=>x.tcp_ping_ms));
 $("#bars").innerHTML=top.map((x,i)=>`<div class="bar" style="--i:${i}"><b style="height:${Math.max(14,100-x.tcp_ping_ms/mx*70)}%"></b><b style="height:${x.is_remixed?24:12}%"></b></div>`).join("")||"";
 $("#xl").innerHTML=top.map(x=>`<span>${Math.round(x.tcp_ping_ms)}</span>`).join("")}
function renderStats(){const s=D.stats||{},n=D.configs.length;$("#alivePct").innerHTML=(n?100:0)+"<small>%</small>";$("#remixChip").textContent="+"+(s.remixed||0);
 $("#upd").textContent=D.updated_at?new Date(D.updated_at).toLocaleString(lang==="fa"?"fa-IR":"en-US"):"—";$("#navCount").textContent=n;$("#navWg").textContent=s.wireguard||0;$("#cnt1").textContent=n}
let ptab="all";
function renderProtos(){const tabs=[["all",t("all")],["clean",t("clean")]];$("#protoTabs").innerHTML=tabs.map(([k,l])=>`<button class="tab ${ptab===k?"on":""}" data-pt="${k}">${l}</button>`).join("");
 const src=D.configs.filter(x=>ptab==="all"||x.is_remixed),c={};src.forEach(x=>c[x.protocol]=(c[x.protocol]||0)+1);
 const rows=Object.entries(c).sort((a,b)=>b[1]-a[1]).slice(0,4);
 $("#protoList").innerHTML=rows.map(([k,v])=>`<div class="row"><span class="ic latin" style="font-size:10px;font-weight:700">${k.slice(0,2).toUpperCase()}</span><div><b>${v}</b><small class="latin">${k==="wireguard"?"WireGuard":k.toUpperCase()}</small></div><button class="ghost" data-all="${k}">${t("copyall")}</button></div>`).join("")||`<div class="empty">—</div>`;
 $$("[data-pt]").forEach(b=>b.onclick=()=>{ptab=b.dataset.pt;renderProtos()});
 $$("[data-all]").forEach(b=>b.onclick=()=>copy(src.filter(x=>x.protocol===b.dataset.all).map(x=>x.config).join("\n")))}
const PT=["all","clean","vless","vmess","trojan","ss","wireguard"];
function mountTable(root,pageSize){
 let n=pageSize;const st={p:"all",q:""};
 root.innerHTML=`<div class="tools"><div class="tabs" style="margin:0"></div><label class="search"><svg class="i" data-ic="search"></svg><input data-ip="search" placeholder="${t("search")}"></label></div><div class="tw"><table><thead><tr><th>${t("server")}</th><th>${t("type")}</th><th>${t("ping")}</th><th>${t("trust")}</th><th></th><th></th></tr></thead><tbody></tbody></table></div><button class="ghost more">${t("more")}</button>`;
 fillIcons(root);const tb=$("tbody",root),tabs=$(".tabs",root),more=$(".more",root);
 const list=()=>D.configs.filter(x=>(st.p==="all"||(st.p==="clean"?x.is_remixed:x.protocol===st.p))&&(!st.q||(x.server+x.port+x.protocol+x.source).toLowerCase().includes(st.q)));
 const draw=()=>{const L=list();view=L;
  tabs.innerHTML=PT.map(k=>`<button class="tab ${st.p===k?"on":""}" data-k="${k}">${k==="all"?t("all"):k==="clean"?t("clean"):k==="wireguard"?"WG":k.toUpperCase()}</button>`).join("");
  tb.innerHTML=L.slice(0,n).map((x,i)=>`<tr data-row="${i}" class="${sel===x?"sel":""}"><td><div class="coin"><i>${pc(x).slice(0,2)}</i>${esc(x.server)}<small>:${esc(x.port)}</small></div></td><td class="latin">${pc(x)}${x.is_remixed?" ✦":""}</td><td><span class="pp ${pcls(x.tcp_ping_ms)}">${x.tcp_ping_ms?Math.round(x.tcp_ping_ms)+" ms":"—"}</span></td><td class="latin">${esc(x.trust_score??"—")}</td><td>${spark(x)}</td><td><button class="pill sm" data-c="${i}">${t("copy")}</button></td></tr>`).join("")||`<tr><td colspan="6" class="empty">${t("empty")}</td></tr>`;
  more.style.display=L.length>n?"":"none";$$("[data-k]",tabs).forEach(b=>b.onclick=()=>{st.p=b.dataset.k;n=pageSize;draw()})};
 tb.onclick=e=>{const c=e.target.closest("[data-c]"),r=e.target.closest("tr[data-row]");if(c){e.stopPropagation();copy(view[c.dataset.c].config);return}if(r){sel=view[r.dataset.row];renderDetail();$$("tr.sel").forEach(x=>x.classList.remove("sel"));r.classList.add("sel")}};
 more.onclick=()=>{n+=pageSize;draw()};$("input",root).oninput=e=>{st.q=e.target.value.toLowerCase().trim();n=pageSize;draw()};draw()}
function renderDetail(){const x=sel||D.configs[0];const el=$("#detail");if(!x){el.innerHTML=`<div class="empty">${t("sel")}</div>`;return}sel=x;
 el.innerHTML=`<div class="logo latin" style="font-weight:700">${pc(x).slice(0,2)}</div><h3 class="latin">${pc(x)} <span class="sub">${x.is_remixed?"· Clean IP":""}</span></h3><dl><dt>${t("server")}</dt><dd>${esc(x.server)}</dd><dt>Port</dt><dd>${esc(x.port)}</dd><dt>${t("ping")}</dt><dd>${x.tcp_ping_ms?Math.round(x.tcp_ping_ms)+" ms":"—"}</dd><dt>${t("origin")}</dt><dd>${esc((x.source||"").split("/")[0])}</dd></dl><div class="btns"><button class="gb" id="dq">QR</button><button class="pill" id="dc">${t("copy")}</button></div>`;
 $("#dc").onclick=()=>copy(x.config);$("#dq").onclick=()=>showQR(x.config)}
function showQR(s){$("#qimg").src="https://api.qrserver.com/v1/create-qr-code/?size=280x280&margin=6&data="+encodeURIComponent(s);$("#qtxt").textContent=s;$("#qr").classList.add("show");$("#qcopy").onclick=()=>copy(s)}
function dl(name,text){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:"text/plain"}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000)}
let mine=[];
function renderWg(){const L=[...mine,...D.configs.filter(x=>x.protocol==="wireguard")];
 $("#wgList").innerHTML=L.map((x,i)=>`<div class="card wgc"><div class="coin"><i>WG</i>${esc(x.server)}<small>:${esc(x.port)}</small></div><div class="sub latin">${x.mine?"Personal":"Cloudflare WARP"}</div><div class="btns"><button class="pill sm" data-wc="${i}">${t("copy")}</button><button class="ghost" data-wd="${i}">${t("download")}</button><button class="ghost" data-wq="${i}">QR</button></div></div>`).join("")||`<div class="empty">${t("nowg")}</div>`;
 $$("[data-wc]").forEach(b=>b.onclick=()=>copy(L[b.dataset.wc].config));$$("[data-wd]").forEach(b=>b.onclick=()=>dl("Xfinder-"+b.dataset.wd+".conf",L[b.dataset.wd].conf));$$("[data-wq]").forEach(b=>b.onclick=()=>showQR(L[b.dataset.wq].conf))}
const b64=u8=>btoa(String.fromCharCode(...u8));
async function genWg(){try{const kp=await crypto.subtle.generateKey({name:"X25519"},true,["deriveBits"]);
 const priv=new Uint8Array(await crypto.subtle.exportKey("pkcs8",kp.privateKey)).slice(-32),pub=new Uint8Array(await crypto.subtle.exportKey("raw",kp.publicKey));
 const r=await fetch("https://api.cloudflareclient.com/v0a2158/reg",{method:"POST",headers:{"Content-Type":"application/json","CF-Client-Version":"a-6.3-1922"},body:JSON.stringify({key:b64(pub),install_id:"",fcm_token:"",type:"Android",locale:"en_US",tos:new Date().toISOString()})});
 const c=(await r.json()).config;const ips=D.configs.filter(x=>x.is_remixed&&x.tcp_ping_ms).map(x=>x.server);const host=ips[Math.floor(Math.random()*ips.length)]||"engage.cloudflareclient.com";
 const conf=`[Interface]\nPrivateKey = ${b64(priv)}\nAddress = ${c.interface.addresses.v4}/32, ${c.interface.addresses.v6}/128\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = ${c.peers[0].public_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = ${host}:2408\nPersistentKeepalive = 25\n`;
 mine.unshift({server:host,port:2408,conf,config:conf,mine:true,protocol:"wireguard"});renderWg();toast(t("genok"))}catch{toast(t("genfail"))}}
function renderSources(){const L=D.source_list&&D.source_list.length?D.source_list:[];$("#srcList").innerHTML=L.map(s=>`<div class="card"><div><b class="latin">${esc(s.name)}</b><div class="sub">${t("count")}: <span class="num">${s.count}</span></div></div><span class="${s.ok?"chip":"chipg"}">${s.trust}</span></div>`).join("")||`<div class="empty">—</div>`}
function renderAll(){renderStats();renderBars();renderProtos();mountTable($("#t1"),8);mountTable($("#t2"),30);renderDetail();renderWg();renderSources()}
// navigation + hamburger
const mob=matchMedia("(max-width:900px)");
$("#burger").onclick=()=>document.body.classList.toggle(mob.matches?"nav-open":"nav-collapsed");
$("#scrim").onclick=()=>document.body.classList.remove("nav-open");
$$(".nav").forEach(b=>b.onclick=()=>{$$(".nav").forEach(x=>x.classList.remove("on"));b.classList.add("on");$$(".sec").forEach(x=>x.classList.remove("on"));$("#"+b.dataset.go).classList.add("on");$("#crumb").textContent=b.querySelector("span").textContent;document.body.classList.remove("nav-open");scrollTo({top:0})});
$("#gs").oninput=e=>{const v=e.target.value;document.querySelector('[data-go="configs"]').click();const i=$("#t2 input");if(i){i.value=v;i.dispatchEvent(new Event("input"))}};
const sw=()=>{lang=lang==="fa"?"en":"fa";applyLang()};$("#lang").onclick=sw;$("#lang2").onclick=sw;
$("#refresh").onclick=async()=>{await load();renderAll();toast(t("refreshed"))};
$("#genWg").onclick=genWg;$("#qx").onclick=()=>$("#qr").classList.remove("show");$("#qr").onclick=e=>{if(e.target.id==="qr")e.target.classList.remove("show")};
const subs=()=>["all","vless","vmess","trojan","ss","hysteria2","wireguard"].map(p=>base+"output/"+p+".txt");
$("#copySub").onclick=()=>copy(base+"output/all.txt");$("#subLinks").onclick=()=>copy(subs().join("\n"));
// loader: سریع، حداکثر ۲.۵ ثانیه
const bar=$("#bar");let p=0;const tick=setInterval(()=>{p=Math.min(90,p+8);bar.style.width=p+"%"},120);
const hide=()=>{clearInterval(tick);bar.style.width="100%";setTimeout(()=>{$("#loader").classList.add("hide");setTimeout(()=>$("#loader").remove(),500)},250)};
const minWait=new Promise(r=>setTimeout(r,1500)),cap=setTimeout(hide,2500);
applyLang();
load().then(()=>{renderAll()}).finally(()=>minWait.then(()=>{clearTimeout(cap);hide()}));
