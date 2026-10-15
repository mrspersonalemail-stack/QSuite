"use strict";
const $ = (s) => document.querySelector(s);
let actor = null, current = "dashboard", generation = 0, terminalSocket = null, terminalView = null;
const titles = {dashboard:"System overview",server:"Server inventory",security:"Security control",performance:"Performance history",backups:"Backup confidence",logs:"Service logs",incidents:"Incident register",terminal:"Isolated terminal",services:"Service operations",settings:"Account & settings"};
function requestedPage() { return QSuiteUI.page(location.pathname, location.search); }
current = requestedPage();
function el(tag, text, cls) { const n = document.createElement(tag); if(text !== undefined) n.textContent = text; if(cls) n.className = cls; return n; }
function append(parent, ...children) { children.forEach(c => parent.append(c)); return parent; }
function csrf() { const item = document.cookie.split("; ").find(c=>c.startsWith("__Host-qsuite-csrf=") || c.startsWith("qsuite-dev-csrf=")); return item ? decodeURIComponent(item.split("=").slice(1).join("=")) : ""; }
async function api(path, method="GET", body) {
  const options = {method,credentials:"same-origin",headers:{}};
  if(method !== "GET") { options.headers={"Content-Type":"application/json","X-CSRF-Token":csrf()}; options.body=JSON.stringify(body ?? {}); }
  const r = await fetch("/api/v1/"+path,options), data = await r.json();
  if(!r.ok) { const message = typeof data.detail === "string" ? data.detail : "Invalid request"; if(r.status===401 && path!=="auth/login") showLogin(); throw new Error(message); }
  return data;
}
let noticeTimer;
function notice(message, severity="info") { clearTimeout(noticeTimer); const box=$("#notice");box.textContent=message;box.className="toast "+severity;box.hidden=false;noticeTimer=setTimeout(()=>{box.hidden=true;},8000); }
function can(permission) { return actor?.permissions.includes(permission); }
function human(bytes) { if(bytes==null) return "Unavailable"; const units=["B","KiB","MiB","GiB","TiB"]; let index=0; while(bytes>=1024&&index<units.length-1){bytes/=1024;index++;} return `${bytes.toFixed(index?1:0)} ${units[index]}`; }
function date(value) { return value ? new Date(value*1000).toLocaleString() : "Unknown"; }
function metric(label,value,subtitle,pct) { const n=el("article",undefined,"card"); append(n,el("div",label,"label"),el("div",value,"value")); if(pct!==undefined){const bar=el("div",undefined,"bar"),fill=el("div",undefined,"bar-fill"+(pct>85?" warn":""));fill.style.width=Math.min(100,Math.max(0,pct))+"%";bar.append(fill);n.append(bar);} n.append(el("div",subtitle,"fine"));return n; }
function card(title) { const n=el("article",undefined,"card"); n.append(append(el("div",undefined,"card-title"),el("h2",title)));return n; }
function row(label,value,css) {return append(el("div",undefined,"row"),el("span",label,"muted"),el("b",value,css));}
function table(columns,rows) {const wrap=el("div",undefined,"table-wrap"),t=el("table"),head=el("thead"),tr=el("tr");columns.forEach(c=>tr.append(el("th",c)));head.append(tr);t.append(head);const b=el("tbody");rows.forEach(values=>{const r=el("tr");values.forEach(v=>r.append(el("td",v==null?"Unknown":String(v))));b.append(r);});t.append(b);wrap.append(t);if(!rows.length)wrap.append(el("div","No records available.","empty"));return wrap;}
function button(text,handler,permission) {const b=el("button",text,"quiet");b.disabled=permission&&!can(permission);b.addEventListener("click",()=>Promise.resolve(handler()).catch(e=>notice(e.message)));return b;}
async function fresh() { return new Promise((resolve,reject)=> { const dialog=$("#reauth"),form=$("#reauth-form"); form.reset();$("#reauth-error").textContent="";dialog.showModal();const cancel=()=>{form.reset();dialog.close();reject(new Error("Operation cancelled"));};$("#reauth-cancel").onclick=cancel;dialog.oncancel=(e)=>{e.preventDefault();cancel();};form.onsubmit=async e=>{e.preventDefault();const d=new FormData(form);try{await api("auth/reauthenticate","POST",{password:d.get("password"),otp:d.get("otp")||null});form.reset();dialog.close();resolve();}catch(error){$("#reauth-error").textContent=error.message;}};}); }
async function operation(path,target="",reauth=false) { if(reauth) await fresh(); const result=await api(path,"POST",{target});notice("Operation queued. Job "+result.job);for(let i=0;i<180;i++){await new Promise(r=>setTimeout(r,2000));const job=await api("jobs/"+result.job);if(!["queued","running"].includes(job.status)){notice("Operation "+job.status+(job.error?": "+job.error:""));const output=el("pre",JSON.stringify(job.result,null,2));$("#content").append(output);return;}}notice("Job still running. Check job "+result.job); }
function showLogin() {closeTerminal();actor=null;if(typeof selectedPackage!=="undefined")selectedPackage=null;$("#content").replaceChildren();$("#login").hidden=false;$("#shell").hidden=true;if(location.pathname!=="/login")history.replaceState(null,"","/login?next="+encodeURIComponent("/panel/"+current));}
async function showShell() {
 actor=await api("auth/me");$("#login").hidden=true;$("#shell").hidden=false;
 $("#identity").textContent=actor.username+" · "+actor.role.replaceAll("_"," ");
 const s=await api("settings");$("#access").textContent=s.access ? "ACCESS "+s.access.toUpperCase() : "COMMUNITY";$("#access").classList.toggle("warn",s.access==="wan");$("#version").textContent=s.version;
 const allowed=QSuiteUI.allowed(actor.permissions,actor.must_change || (actor.mfa_required&&!actor.mfa));
 const nav=$("#nav");nav.replaceChildren();let group=null;
 for(const [page,label,icon,section] of allowed){if(section!==group&&section){nav.append(el("div",section,"nav-label"));}group=section;const b=append(el("button"),el("span",icon,"nav-icon"),el("span",label));b.dataset.page=page;nav.append(b);}
 if(!allowed.some(n=>n[0]===current))current=allowed[0]?.[0]||"settings";
 history.replaceState(null,"","/panel/"+current);await render();
}
$("#login-form").addEventListener("submit",async e=>{e.preventDefault();const form=e.target,d=new FormData(form);$("#login-error").textContent="";try{await api("auth/login","POST",{username:d.get("username"),password:d.get("password"),otp:d.get("otp")||null});form.reset();await showShell();}catch(error){$("#login-error").textContent=error.message;}});
$("#logout").onclick=async()=>{try{await api("auth/logout","POST",{});}finally{showLogin();}};
$("#refresh").onclick=()=>render();
function closeMenu(){ $("#sidebar").classList.remove("menu-open"); $("#mobile-menu").setAttribute("aria-expanded","false"); }
$("#mobile-menu").onclick=()=>{const opened=$("#sidebar").classList.toggle("menu-open");$("#mobile-menu").setAttribute("aria-expanded",String(opened));};
document.addEventListener("keydown",e=>{if(e.key==="Escape"){closeMenu();}});
$("#nav").addEventListener("click",e=>{const b=e.target.closest("button[data-page]");if(b){closeTerminal();current=b.dataset.page;history.pushState(null,"","/panel/"+current);closeMenu();render();}});
window.addEventListener("popstate",()=>{closeTerminal();current=requestedPage();showShell().catch(()=>showLogin());});
async function render() {
 const mine=++generation;$("#heading").textContent=current==="dashboard"&&!can("system.view")?"Community overview":titles[current]||current;$("#subtitle").textContent=can("system.view")?"Live state. Evidence where it matters.":"Minecraft, community updates and your approved tools.";$("#page-name").textContent=current[0].toUpperCase()+current.slice(1);$("#notice").hidden=true;$("#content").replaceChildren(loading());$("#nav").querySelectorAll("button").forEach(b=>b.classList.toggle("active",b.dataset.page===current));
 try{const result=await pages[current]();if(mine!==generation)return;$("#content").replaceChildren(result);result.classList.add("page-enter");$("#updated").textContent="Updated "+new Date().toLocaleTimeString();$("#connection").textContent="Connected";}catch(error){if(mine!==generation)return;$("#content").replaceChildren(el("div",error.message,"callout"));$("#connection").textContent="Check connection";}
}
function plot(samples,key,label) {const ns="http://www.w3.org/2000/svg",svg=document.createElementNS(ns,"svg");svg.setAttribute("viewBox","0 0 650 180");svg.classList.add("chart");svg.setAttribute("role","img");svg.setAttribute("aria-label",label);const values=samples.map(s=>s[key]).filter(v=>typeof v==="number"&&Number.isFinite(v));if(!values.length)return el("div","No history for this measurement.","empty");const max=key==="cpu_pct"?100:Math.max(...values,1);[0,1,2,3].forEach(i=>{const l=document.createElementNS(ns,"line");l.setAttribute("x1","30");l.setAttribute("x2","645");l.setAttribute("y1",String(10+i*45));l.setAttribute("y2",String(10+i*45));svg.append(l);});const p=document.createElementNS(ns,"polyline");p.setAttribute("points",values.map((v,i)=>`${30+i*615/Math.max(1,values.length-1)},${145-v/max*125}`).join(" "));svg.append(p);const t=document.createElementNS(ns,"text");t.setAttribute("x","30");t.setAttribute("y","176");t.textContent=`${values.length} samples · max ${max.toFixed(1)}`;svg.append(t);return svg;}
const pages = {
 dashboard:async()=>{const [s,services,b]=await Promise.all([api("status"),api("services"),api("backups")]);const root=el("div"),grid=el("div",undefined,"grid");grid.append(metric("CPU",s.cpu_percent.toFixed(1)+"%",`${s.cpu_temperature??"Unknown"} °C · load ${s.load[0].toFixed(2)}`,s.cpu_percent),metric("Memory",human(s.memory.used),`${human(s.memory.available)} available`,s.memory.percent),metric("Root storage",human(s.disks[0]?.free),"Available on root filesystem",s.disks[0]?.percent??0),metric("Uptime",Math.floor(s.uptime/3600)+" h",s.hostname));root.append(grid);const two=el("div",undefined,"grid two stack"),system=card("Host & network"),service=card("Service health");system.append(row("Operating system",s.os),row("Kernel",s.kernel),row("Hostname",s.hostname),row("Addresses",s.addresses.map(a=>a.address).join(", ")));services.services.forEach(v=>service.append(row(v.id,v.ActiveState||"unknown","state"+(v.ActiveState==="active"?"":" unknown"))));two.append(system,service);root.append(two);const backup=card("Recovery confidence");backup.append(row("Latest archive",b.archives[0]?.id??"Unavailable"),row("Logical world integrity",b.logical_integrity??"Unknown"),row("Off-server transfer",b.offsite?.state??"Unknown"));if(b.world_warning)backup.append(el("p","Recovered world has a retained warning. Archive CRC does not prove world consistency.","callout"));root.append(append(el("div",undefined,"stack"),backup));return root;},
 server:async()=>{const s=await api("status"),n=card("System inventory");n.append(row("Hostname",s.hostname),row("Operating system",s.os),row("Kernel",s.kernel),row("Swap",human(s.swap.used)+" / "+human(s.swap.total)),table(["Interface","Address"],s.addresses.map(a=>[a.interface,a.address])),table(["Mount","Total","Free","Usage"],s.disks.map(d=>[d.mount,human(d.total),human(d.free),d.percent==null?"Unknown":d.percent+"%"])),el("h3","Minecraft integration"),el("p",s.minecraft.configured?"Detected through configured server path. Player count, TPS and MSPT remain unavailable without a trusted metrics interface.":"No Minecraft integration configured.","muted"));return n;},
 security:async()=>{const [s,e,p]=await Promise.all([api("security"),api("security/events"),api("security/protocols")]);const n=el("div"),g=el("div",undefined,"grid");g.append(metric("Security level",s.level==null?"Unknown":"L"+s.level,s.state),metric("Enforcement",s.enforcement??"Unavailable","Automatic bans are disabled"),metric("Scanner",s.scanner,"Coverage must be verified"),metric("Security webhook",s.webhook_configured?"Configured":"Not configured","Separate from ordinary alerts"));n.append(g,el("p",s.geography??"Geography unavailable","callout"));const c=card("Recent protocols");c.append(table(["Time","Protocol","Level","Source","Summary"],e.events.map(v=>[date(v.ts),v.protocol,"L"+v.level,v.source??"UNKNOWN",v.summary])));const controls=el("div",undefined,"actions");controls.append(button("Quick scan",()=>operation("security/scan","quick"),"security.scan"),button("Full scan",()=>operation("security/scan","full"),"security.scan"),button("Approve integrity baseline",async()=>{if(confirm("Approve current protected files as trusted? Review changes first."))await operation("security/baseline","update",true);},"security.baseline"));c.append(controls);n.append(append(el("div",undefined,"stack"),c));const definitions=card("Protocol vocabulary");definitions.append(table(["Protocol","Default level","Description","Response"],p.protocols.map(v=>[v.name,v.level,v.description,v.response])));n.append(append(el("div",undefined,"stack"),definitions));return n;},
 performance:async()=>{const n=el("div"),tabs=el("div",undefined,"tabs"),c=card("CPU activity"),body=el("div");for(const w of ["1h","6h","24h","7d","30d"]){const b=button(w,async()=>{tabs.querySelectorAll("button").forEach(x=>x.classList.toggle("active",x===b));const h=await api("performance/"+w);body.replaceChildren(plot(h.samples,"cpu_pct","CPU history"),el("p","Source: "+h.source+". Missing values are not estimated.","fine"));});tabs.append(b);}n.append(tabs,c);c.append(body);const h=await api("performance/24h");body.append(plot(h.samples,"cpu_pct","CPU history"));return n;},
 backups:async()=>{const b=await api("backups"),n=card("Backup archives");n.append(el("p",b.creation_available?"Backup creation available.":"Backup creation remains with existing manager. No API credential configured.","muted"),el("p","Restore verification uses an isolated copy. Production restore is not exposed.","callout"),table(["Archive","Created","Size"],b.archives.map(v=>[v.id,date(v.modified),human(v.size)])));const a=el("div",undefined,"actions");a.append(button("Validate latest",()=>operation("backups/validate"),"backups.validate"),button("Verify isolated restore",()=>operation("restore/verify","",true),"restore.verify"));n.append(a);return n;},
 logs:async()=>{const s=await api("services"),n=card("Bounded service journal"),select=el("select"),output=el("pre","Select a service.");s.services.forEach(v=>{const o=el("option",v.id);o.value=v.id;select.append(o);});const show=async()=>{try{output.textContent=(await api("logs/"+encodeURIComponent(select.value))).output;}catch(e){output.textContent=e.message;}};select.onchange=show;n.append(select,output);if(s.services.length)await show();return n;},
 incidents:async()=>{const s=await api("incidents"),n=card("Security incidents");n.append(table(["Time","ID","Protocol","Severity","Status","Summary"],s.incidents.map(v=>[date(v.ts),v.id.slice(0,12),v.protocol,"L"+v.level,v.status,v.summary])),append(el("div",undefined,"actions"),button("Capture sanitized legacy bundle",()=>operation("incidents/capture"),"incident.capture")));return n;},
 services:async()=>{const s=await api("services"),n=card("Allowlisted services");n.append(el("p","Critical SSH and security services cannot be stopped from this interface. Crafty operations affect its managed workloads.","callout"));for(const v of s.services){const r=row(v.id,v.ActiveState??"unknown"),a=el("div",undefined,"actions");for(const op of ["start","stop","restart"]){const control=button(op,async()=>{if(confirm(`${op} ${v.id}? Crafty operations can interrupt players.`))await operation("services/"+op,v.id,true);},"services.operate");control.disabled=control.disabled||!v.controllable;a.append(control);}r.append(a);n.append(r);}return n;},
 terminal:async()=>{const s=await api("settings"),n=card("Unprivileged live terminal");n.append(el("p","Separate OS account. No root shell, no API helper privileges. Idle limit 5 minutes; maximum lifetime 1 hour.","callout"));if(!s.terminal_enabled){n.append(el("div","Terminal disabled until installation boundary is validated.","empty"));return n;}const screen=el("div");screen.id="terminal-screen";n.append(button("Open terminal",async()=>{await fresh();const t=await api("terminal/ticket","POST",{});if(!window.Terminal)throw new Error("Terminal assets unavailable");closeTerminal();terminalView=new window.Terminal({cols:90,rows:22,theme:{background:"#0d1215",foreground:"#edf3f2",cursor:"#88e0b7"},fontSize:13});terminalView.open(screen);terminalSocket=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/api/v1/terminal");terminalSocket.binaryType="arraybuffer";terminalSocket.onopen=()=>{terminalSocket.send(t.ticket);terminalView.focus();};terminalSocket.onmessage=e=>{if(terminalView)terminalView.write(new Uint8Array(e.data));};terminalSocket.onclose=()=>{if(terminalView)terminalView.writeln("\r\n[Session closed]");};terminalView.onData(data=>{if(terminalSocket?.readyState===WebSocket.OPEN)terminalSocket.send(data);});},"terminal.open"),screen);return n;},
 settings: async () => {
   const s = await api("settings"), n = card("Access & account");
   n.append(row("Access mode", s.access.toUpperCase()), row("Origin", s.origin), row("User", actor.username),
     row("Role", actor.role), row("2FA", actor.mfa ? "Enabled" : "Not enrolled"),
     el("p", "WAN changes require validated TLS and local privileged configuration.", "muted"));
   const toggleLabel = el("label", undefined, "switch"), toggle = el("input");
   toggle.type = "checkbox"; toggle.checked = s.require_trusted_tls; toggle.disabled = !can("access.change");
   toggleLabel.append(toggle, el("span", "Require trusted TLS for WAN")); n.append(toggleLabel);
   n.append(el("p", "When off, WAN still uses HTTPS. Self-signed certificates require manual browser trust. Enable after installing a CA-issued certificate.", "fine"));
   toggle.addEventListener("change", async () => {
     const wanted = toggle.checked; toggle.disabled = true;
     try { await fresh(); await api("access/tls-policy", "POST", {target: wanted ? "required" : "optional"});
       notice(wanted ? "Trusted TLS is required for WAN." : "Trusted certificate requirement disabled. HTTPS remains required.");
     } catch (error) { toggle.checked = !wanted; notice(error.message); }
     finally { toggle.disabled = !can("access.change"); }
   });
   if (!actor.mfa) {
     n.append(button("Enroll TOTP 2FA", async () => {
       await fresh();
       const result = await api("auth/totp/enroll", "POST", {}), box = card("Add this account to your authenticator");
       box.append(el("pre", result.uri), el("p", "Treat enrollment URI as secret. Recovery codes appear only once.", "muted"));
       const input = el("input"); input.placeholder = "6-digit code"; input.maxLength = 6;
       box.append(input, button("Confirm 2FA", async () => {
         const data = await api("auth/totp/confirm", "POST", {otp: input.value});
         box.replaceChildren(el("h2", "Save recovery codes now"), el("pre", data.recovery_codes.join("\n")),
           el("p", "Each code works once. Store outside this server.", "callout"));
         actor = await api("auth/me");
       }));
       n.append(box);
     }));
   }
   n.append(append(el("div", undefined, "actions"), button("Revoke all my sessions", async () => {
     await fresh(); await api("auth/sessions/revoke", "POST", {}); showLogin();
   })));
   return n;
 }
};
function closeTerminal(){if(terminalSocket){terminalSocket.close();terminalSocket=null;}if(terminalView){terminalView.dispose();terminalView=null;}}
window.addEventListener("pagehide",closeTerminal);
