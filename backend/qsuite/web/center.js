"use strict";
/* Capability-driven pages reuse the existing session, CSRF and terminal client. */
Object.assign(titles, {packages:"Your control center",minecraft:"Minecraft",crafty:"Crafty controller",
  membernews:"Member News",adminnews:"Admin News",notifications:"Notification routing",
  users:"Users & permissions",audit:"Audit trail",settings:"Your account & settings"});
let selectedPackage = null;
function navigate(page) { current=page;history.pushState(null,"","/panel/"+page);closeMenu();render(); }
function loading() {
  const root=el("div",undefined,"grid two"),label=el("span","Reading permitted information…","sr-only");root.append(label);
  for(let i=0;i<4;i++){const c=el("div",undefined,"card skeleton");c.setAttribute("aria-hidden","true");c.append(el("div"),el("div"),el("div"));root.append(c);}return root;
}
function field(label, type="text", value="") {
  const wrap=el("label",label),input=el(type==="textarea"?"textarea":"input");
  if(type!=="textarea")input.type=type;input.value=value;wrap.append(input);return {wrap,input};
}
function selectField(label, options, selected) {
  const wrap=el("label",label),input=el("select");
  options.forEach(([value,text])=>{const o=el("option",text);o.value=value;input.append(o);});
  if(selected!==undefined)input.value=selected;wrap.append(input);return {wrap,input};
}
function toggle(label, checked=false) {
  const wrap=el("label",undefined,"switch"),input=el("input");input.type="checkbox";input.checked=checked;
  append(wrap,input,el("span",label));return {wrap,input};
}
function badge(text, level) { return el("span",text,"severity"+(level!==undefined?" level-"+level:"")); }
function confirmAction(title, message, action="Confirm") {
  return new Promise(resolve=>{
    const dialog=el("dialog",undefined,"confirmation"),form=el("form"),actions=el("div",undefined,"actions");
    const cancel=button("Cancel",()=>{dialog.close();resolve(false);dialog.remove();});
    const accept=button(action,()=>{dialog.close();resolve(true);dialog.remove();});accept.className="danger";
    append(form,el("h2",title),el("p",message,"muted"),append(actions,cancel,accept));dialog.append(form);document.body.append(dialog);
    dialog.oncancel=()=>{resolve(false);dialog.remove();};dialog.showModal();cancel.focus();
  });
}
function empty(title,message) { const n=el("div",undefined,"empty-state");append(n,el("div","◇","empty-icon"),el("h3",title),el("p",message,"muted"));return n; }
function dataView(value, depth=0) {
  if(value===null||value===undefined)return el("span","Unavailable","muted");
  if(typeof value!=="object")return el("span",String(value));
  if(depth>3)return el("pre",JSON.stringify(value,null,2));
  const root=el("div",undefined,"data-view");
  const entries=Array.isArray(value)?value.slice(0,20).map((v,i)=>[String(i+1),v]):Object.entries(value);
  if(!entries.length)return empty("Nothing recorded yet","This package will report evidence when it becomes available.");
  for(const [key,v] of entries){
    if(typeof v==="object"&&v!==null){const details=el("details",undefined,"accordion");details.append(el("summary",key.replaceAll("_"," ")),dataView(v,depth+1));root.append(details);}
    else root.append(row(key.replaceAll("_"," "),v==null?"Unavailable":typeof v==="boolean"?(v?"Yes":"No"):String(v)));
  }return root;
}
function newsEntry(event, admin=false) {
  const n=el("article",undefined,"news-entry"+(admin?" security-state level-"+event.level:""));
  const head=el("div",undefined,"entry-heading");head.append(el("h3",event.title));
  if(admin)head.append(badge("L"+event.level,event.level));if(event.test)head.append(badge("TEST"));
  n.append(head,el("p",event.message),el("div",date(event.ts)+" · "+(event.delivery_status||"Dashboard"),"fine"));
  if(can((admin?"admin":"member")+"_news.configure")&&["failed","unconfigured"].includes(event.delivery_status))n.append(button("Retry delivery",async()=>{await fresh();await api("news/"+(admin?"admin":"member")+"/"+event.id+"/retry","POST",{});notice("Delivery retry queued.","success");render();}));
  if(admin){const detail=el("details",undefined,"accordion");detail.append(el("summary","Alert context"),row("Package",event.package),row("Protocol",event.protocol||"—"),row("Incident",event.incident||"—"),row("Attempts",event.attempts??0));if(event.error)detail.append(el("p",event.error,"callout"));n.append(detail);}return n;
}

pages.dashboard=async()=>{
  const {widgets:w}=await api("dashboard"),root=el("div"),hero=el("div",undefined,"hero-panel");
  append(hero,el("div",can("system.view")?"OPERATIONS AT A GLANCE":"YOUR COMMUNITY CONTROL ROOM","eyebrow"),el("h2","Welcome back, "+actor.username+"."),el("p",can("system.view")?"Server evidence, recovery confidence and alerts in one place.":"Your Minecraft community, with the tools your role can use.","muted"));root.append(hero);
  const grid=el("div",undefined,"grid stack");
  if(w.system?.memory){const s=w.system;grid.append(metric("CPU",s.cpu_percent.toFixed(1)+"%","Current activity",s.cpu_percent),metric("Memory",human(s.memory.used),human(s.memory.available)+" available",s.memory.percent),metric("Storage",human(s.disks[0]?.free),"Free on root",s.disks[0]?.percent??0),metric("Uptime",Math.floor(s.uptime/3600)+" h",s.hostname));}
  if(w.minecraft){const g=w.minecraft;grid.append(metric("Minecraft",g.online?"Online":"Offline",g.version||"Status interface unavailable"),metric("Players",g.players??"—",g.max_players!=null?"of "+g.max_players+" slots":"Player count unavailable"),metric("Game uptime",g.uptime!=null?Math.floor(g.uptime/3600)+" h":"—","TPS requires a metrics integration"));}
  if(w.security)grid.append(metric("QSecurity",w.security.level==null?"Unknown":"L"+w.security.level,w.security.state||"Observation"));
  if(w.crafty)grid.append(metric("Crafty",w.crafty.state||"Unknown","Manager service"));root.append(grid);
  const panels=el("div",undefined,"grid two stack");
  if(w.backups){const c=card("Recovery confidence");c.append(row("Latest archive",w.backups.archives?.[0]?.id||"Unavailable"),row("Logical integrity",w.backups.logical_integrity||"Unproven"),button("Open backups",()=>navigate("backups")));panels.append(c);}
  if(w.services){const c=card("Service health");(w.services.services||[]).forEach(s=>c.append(row(s.id,s.ActiveState||"Unknown","state")));panels.append(c);}
  for(const [key,label,isAdmin] of [["admin_news","Private alerts",true],["member_news","Community updates",false]]){
    if(Object.hasOwn(w,key)){const c=card(label);if(w[key].length)w[key].slice(0,3).forEach(e=>c.append(newsEntry(e,isAdmin)));else c.append(empty("All caught up","New updates will appear here."));c.append(button("Open "+label.toLowerCase(),()=>navigate(isAdmin?"adminnews":"membernews")));panels.append(c);}
  }
  if(!Object.keys(w).length){const c=card("Your permitted logs");c.append(empty("Read only, focused access","Open Logs to inspect the sources assigned to your role."),button("Open logs",()=>navigate("logs")));panels.append(c);}root.append(panels);return root;
};

pages.minecraft=async()=>{
  const s=await api("minecraft"),n=card("Minecraft status");n.append(badge(s.online?"● ONLINE":"○ OFFLINE"),dataView(s));
  if(can("logs.minecraft.read"))n.append(button("Player activity",()=>navigate("logs")));
  if(can("packages.view"))n.append(button("Open QMC",()=>{selectedPackage="qmc";navigate("packages");}));return n;
};
pages.crafty=async()=>{const s=await api("crafty"),n=card("Crafty manager");n.append(badge(s.state||"Unknown"),el("p","Crafty manages your game processes. Its service controls can interrupt those workloads.","muted"),dataView(s));if(can("packages.view"))n.append(button("Manager controls",()=>{selectedPackage="crafty";navigate("packages");}));return n;};

pages.backups=async()=>{
  const b=await api("backups"),root=el("div",undefined,"stack"),n=card("Download a backup");
  n.append(el("p","Save an archive directly to this computer or phone. Your browser handles the download and can resume interrupted transfers.","muted"));
  const needsMfa=b.download_requires_mfa&&!actor.mfa;
  if(can("backup.download")&&needsMfa){
    const note=el("div",undefined,"callout");note.append(el("p","Enable 2FA in Account & settings before downloading backups over WAN."),button("Open account settings",()=>navigate("settings")));n.append(note);
  }
  if(b.world_warning)n.append(el("p","This installation retains a world-corruption warning. Downloading an archive does not verify that every world chunk or plugin record is recoverable.","callout"));
  const list=el("div",undefined,"backup-list");
  for(const archive of b.archives||[]){
    const item=el("div",undefined,"backup-item"),details=el("div",undefined,"backup-details");
    details.append(el("b",archive.id),el("div",date(archive.modified)+" · "+human(archive.size),"fine"));item.append(details);
    if(can("backup.download")){
      const save=button("↓ Download",async()=>{
        save.disabled=true;
        try{
          await fresh();
          const url="/api/v1/backups/"+encodeURIComponent(archive.id)+"/download";
          const response=await fetch(url,{method:"HEAD",credentials:"same-origin"});
          if(!response.ok)throw new Error(response.status===401?"Sign in again before downloading.":response.status===429?"Two downloads are already active. Try again shortly.":"Backup unavailable or download authorization expired. Refresh and try again.");
          const link=el("a");link.href=url;link.download=archive.id;document.body.append(link);link.click();link.remove();
          notice("Download requested. Check your browser's Downloads list.","success");
        }finally{save.disabled=needsMfa||archive.downloadable===false;}
      });
      save.disabled=needsMfa||archive.downloadable===false;
      save.title=needsMfa?"Enable 2FA first":archive.downloadable===false?"Archive is incomplete or unavailable":"Download to your device";
      item.append(save);
    }
    list.append(item);
  }
  if(!(b.archives||[]).length)list.append(empty("No completed backups listed","Existing manager backups will appear here."));
  n.append(list);root.append(n);
  const confidence=card("Recovery confidence"),actions=el("div",undefined,"actions");
  confidence.append(row("Logical world integrity",b.logical_integrity||"Unproven"),row("Off-server copy",b.offsite?.state||"Unknown"),el("p",b.creation_available?"Backup creation is available.":"Backup creation remains in Crafty. Validation and isolated restore checks are available here.","muted"));
  if(can("backup.run"))actions.append(button("Validate latest",()=>operation("backups/validate")));
  if(can("backup.restore"))actions.append(button("Verify isolated restore",()=>operation("restore/verify","",true)));
  confidence.append(actions);root.append(confidence);return root;
};

async function configurationForm(name, selectedKeys=null) {
  const config=await api("packages/"+name+"/configuration");
  if(!config.available)return empty("Configuration unavailable",config.reason);
  const n=card(selectedKeys?"VPN & proxy protection settings":"Package settings"),form=el("form"),controls={};n.append(el("p",config.scope,"fine"));
  for(const [key,schema] of Object.entries(config.schema.properties)){
    if(selectedKeys&&!selectedKeys.includes(key))continue;
    const value=config.values[key],label=schema.title||key.replaceAll("_"," ");let control;
    if(schema.type==="boolean")control=toggle(label,value);
    else if(schema.enum)control=selectField(label,schema.enum.map(v=>[v,v]),value);
    else if(schema.type==="integer"){control=field(label,"number",value);control.input.min=schema.minimum??"";control.input.max=schema.maximum??"";control.input.step="1";}
    else if(schema.type==="array")control=field(label+" · one per line","textarea",value.join("\n"));
    else if(schema.type==="object")control=field(label+" · JSON map","textarea",JSON.stringify(value,null,2));
    else control=field(label,"text",value);
    controls[key]={...control,schema};form.append(control.wrap);
  }
  const preview=el("div"),submit=el("button","Preview changes");submit.type="submit";form.append(submit,preview);n.append(form);
  form.onsubmit=async e=>{e.preventDefault();try{
    const values={...config.values};for(const [key,{input,schema}] of Object.entries(controls))values[key]=schema.type==="boolean"?input.checked:schema.type==="integer"?Number(input.value):schema.type==="array"?input.value.split(/\n|,/).map(x=>x.trim()).filter(Boolean):schema.type==="object"?JSON.parse(input.value):input.value;
    const diff=await api("packages/"+name+"/configuration/preview","POST",{values});preview.replaceChildren(el("h3","Review before applying"),table(["Setting","Before","After"],diff.changes.map(k=>[k,JSON.stringify(diff.before[k]),JSON.stringify(diff.after[k])])),el("p","Applies to: "+diff.applies_to,"fine"));
    const apply=button("Apply reviewed changes",async()=>{if(!await confirmAction("Apply configuration","Apply these validated settings to "+name+"? A rollback copy will be retained."))return;await fresh();await api("packages/"+name+"/configuration/apply","POST",{values,expected:diff.expected});notice("Configuration verified and saved.","success");render();});preview.append(apply);
  }catch(error){notice(error.message,"error");}};return n;
}
const securityOverview=pages.security;
pages.security=async()=>{
  const root=await securityOverview(),panel=card("VPN & proxy protection"),state=await api("security/network-protection");
  panel.append(badge(state.enabled?"ENABLED":"DISABLED"),row("Firewall · last observed",state.active?"Blocking known exits":"Not active"),row("Feed state",state.phase),row("Last successful update",date(state.updated)),row("Firewall observation",date(state.observed)));
  panel.append(el("p","Optional QSecurity add-on. Disabled by default. Drops listed VPN, open-proxy and Tor exit sources at the host firewall before applications receive them. IPv4 and IPv6 are covered.","muted"));
  panel.append(el("p",state.limitations+" This cannot prevent packets reaching your internet connection or replace upstream DDoS protection.","callout"));
  if(!state.available)panel.append(el("p","Install the QSuite network guard units, UFW and ipset before enabling. QSuite will not enable or reset UFW for you.","callout"));
  for(const [name,count] of Object.entries(state.feed_counts))panel.append(row(name.replaceAll("_"," ")+" entries",count));
  root.prepend(panel);
  if(can("security.configure")&&can("packages.view"))root.insertBefore(await configurationForm("qsecurity",["vpn_protection_enabled","vpn_allow_cidrs"]),panel.nextSibling);
  return root;
};
pages.packages=async()=>{
  if(selectedPackage){const p=await api("packages/"+encodeURIComponent(selectedPackage)),root=el("div"),n=card(p.label);n.append(button("← All packages",()=>{selectedPackage=null;render();}),el("p",p.help,"muted"),badge(p.installed?"INSTALLED":"NOT INSTALLED"),el("div","Version: "+p.version,"fine"),dataView(p.status));
    const actions=el("div",undefined,"actions");for(const [id,a] of Object.entries(p.actions)){const b=button(a.label,async()=>{if(a.confirmation&&!await confirmAction(a.label,a.confirmation,a.label))return;if(a.fresh_auth)await fresh();const result=await api("packages/"+p.name+"/actions/"+id,"POST",{});notice("Action queued · "+result.job);await watchJob(result.job);});b.disabled=!p.installed;actions.append(b);}n.append(actions);root.append(n);
    if(p.configure)root.append(append(el("div",undefined,"stack"),await configurationForm(p.name)));
    if(p.recent_events.length){const c=card("Recent changes");c.append(table(["Time","Action","Result"],p.recent_events.map(e=>[date(e.ts),e.action,e.result])));root.append(append(el("div",undefined,"stack"),c));}return root;
  }
  const {packages:list}=await api("packages"),root=el("div"),grid=el("div",undefined,"grid packages-grid");
  root.append(el("p","Explore your installed tools and the controls available to your account.","muted"));
  list.forEach(p=>{const c=card(p.label);c.append(badge(p.service_state?"● "+p.service_state.toUpperCase():p.installed?"● AVAILABLE":"○ NOT INSTALLED"),el("p",p.help,"muted"),el("div",p.version,"fine"),button("Open package →",()=>{selectedPackage=p.name;render();}));grid.append(c);});root.append(grid);return root;
};
async function watchJob(id){
  for(let i=0;i<180;i++){await new Promise(r=>setTimeout(r,2000));const j=await api("jobs/"+id);if(!["queued","running"].includes(j.status)){notice("Action "+j.status,j.status==="succeeded"?"success":"error");const box=card("Operation result");box.append(dataView(j.result||{error:j.error}));$("#content").append(box);return;}}notice("Action still running. Job "+id);
}

pages.logs=async()=>{
  const {sources}=await api("log-sources"),n=card("Your authorized log sources");
  if(!sources.length){n.append(empty("No log sources assigned","An Owner can grant specific log permissions through a custom role."));return n;}
  const select=selectField("Source",sources.map(s=>[s.id,s.label])),output=el("pre"),scope=el("p",undefined,"fine");
  async function show(){try{const data=await api("logs/"+encodeURIComponent(select.input.value));output.textContent=data.lines?data.lines.map(l=>l.time+" · "+l.message).join("\n")||"No permitted player activity recorded.":data.output;scope.textContent=data.scope||"Bounded, redacted journal output.";}catch(error){output.textContent=error.message;}}
  select.input.onchange=show;n.append(select.wrap,scope,output);await show();return n;
};

pages.membernews=async()=>{
  const state=await api("news/member"),root=el("div"),health=card("Community channel");health.append(badge(state.health.health.toUpperCase()),el("p","Public announcements only. This channel contains community information.","muted"));root.append(health);
  if(can("member_news.send")){
    const c=card("Compose an announcement"),form=el("form"),title=field("Title"),message=field("Message","textarea"),style=selectField("Style",["INFO","MAINTENANCE","EVENT","UPDATE","DOWNTIME","ONLINE"].map(x=>[x,x]));
    title.input.required=true;title.input.maxLength=120;message.input.required=true;message.input.maxLength=1500;message.input.rows=5;
    const preview=el("div",undefined,"discord-preview"),actions=el("div",undefined,"actions");
    const body=()=>({title:title.input.value,message:message.input.value,style:style.input.value});
    actions.append(button("Preview",async()=>{const p=await api("news/member/preview","POST",body());preview.replaceChildren(el("div","QSuite · Member News","fine"),el("h3",p.embeds[0].title),el("p",p.embeds[0].description),el("div","No Discord mentions","fine"));}));
    const send=el("button","Publish announcement");send.type="submit";actions.append(send);form.append(title.wrap,message.wrap,style.wrap,preview,actions);
    form.onsubmit=async e=>{e.preventDefault();if(!await confirmAction("Publish Member News","This message may be completely public. Review it for sensitive information before publishing.","Publish"))return;try{const result=await api("news/member","POST",body());form.reset();notice(result.queued?"Announcement saved; Discord delivery queued.":"Announcement saved. Member News routing is disabled.","success");render();}catch(error){notice(error.message,"error");}};c.append(form);root.append(append(el("div",undefined,"stack"),c));
  }
  const history=card("Community history");state.events.length?state.events.forEach(e=>history.append(newsEntry(e))):history.append(empty("Your next chapter starts here","Announcements and community updates will appear here."));root.append(append(el("div",undefined,"stack"),history));return root;
};
pages.adminnews=async()=>{
  const root=el("div"),filters=card("Private operational alerts"),grid=el("div",undefined,"form-grid"),level=selectField("Severity",[["","All levels"],...[0,1,2,3,4,5].map(l=>[String(l),"L"+l])]),delivery=selectField("Delivery",[["","All states"],...["dashboard","queued","delivered","retry","failed","unconfigured"].map(s=>[s,s])]),packageField=field("Package"),protocol=field("Protocol"),since=field("Since","datetime-local"),list=el("div");
  grid.append(level.wrap,delivery.wrap,packageField.wrap,protocol.wrap,since.wrap);filters.append(grid);root.append(filters,append(el("div",undefined,"stack"),list));
  async function update(){const q=new URLSearchParams();if(level.input.value)q.set("level",level.input.value);if(delivery.input.value)q.set("delivery",delivery.input.value);if(packageField.input.value)q.set("package",packageField.input.value);if(protocol.input.value)q.set("protocol",protocol.input.value);if(since.input.value)q.set("since",Math.floor(new Date(since.input.value).getTime()/1000));const s=await api("news/admin?"+q);list.replaceChildren();const status=card("Notification health");status.append(badge(s.health.health.toUpperCase()),row("L2 administrator target",s.health.policy.level_2_admin_user_id||"Not configured"),row("Last delivery",date(s.health.last_delivery?.delivered)),row("Independent watchdog",s.health.watchdog?.health||"Unavailable"),el("p","L1: no mention · L2: configured administrator · L3–L5: everyone, according to Owner policy.","fine"));list.append(status);s.events.length?s.events.forEach(e=>list.append(newsEntry(e,true))):list.append(empty("No alerts in this view","Change filters to inspect other private events."));}
  filters.append(button("Apply filters",update));await update();return root;
};

pages.notifications=async()=>{
  const root=el("div");
  for(const channel of ["member","admin"]){if(!can(channel+"_news.configure"))continue;
    const state=await api("news/"+channel),c=card(channel==="member"?"Member News · public":"Admin News · private"),form=el("form"),secret=field("Replace webhook · stored value is never returned","password");secret.input.autocomplete="new-password";secret.input.maxLength=350;
    c.append(row("Configured",state.health.configured?"YES · ********":"NO"),badge(state.health.health.toUpperCase()));form.append(secret.wrap);
    let target,mentionAdmin,mentionEveryone;
    if(channel==="admin"){target=field("Level 2 mention target · Discord USER ID","text",state.health.policy.level_2_admin_user_id||"");target.input.inputMode="numeric";target.input.pattern="[0-9]{15,22}";mentionAdmin=toggle("L2 mentions this administrator",state.health.policy.l2_mentions_admin);mentionEveryone=toggle("L3–L5 mentions everyone",state.health.policy.l3_plus_mentions_everyone);form.append(target.wrap,mentionAdmin.wrap,mentionEveryone.wrap);}
    const save=el("button","Save notification settings");save.type="submit";form.append(save);form.onsubmit=async e=>{e.preventDefault();try{await fresh();const body={};if(secret.input.value)body.webhook=secret.input.value;if(channel==="admin")body.policy={level_2_admin_user_id:target.input.value||null,l2_mentions_admin:mentionAdmin.input.checked,l3_plus_mentions_everyone:mentionEveryone.input.checked};await api("news/"+channel+"/configuration","PUT",body);secret.input.value="";notice("Notification settings saved.","success");render();}catch(error){secret.input.value="";notice(error.message,"error");}};c.append(form);
    if(can("admin_news.test")){const actions=el("div",undefined,"actions");for(const l of channel==="member"?[1]:[1,2,3]){const testButton=button(channel==="member"?"Test Member News":l===1?"Test Admin News":"Test L"+l+" alert",async()=>{if(!await confirmAction("Send TEST alert",l>=3?"This TEST can mention everyone in the private Discord channel.":"Send a clearly marked TEST notification to this channel?","Send test"))return;await fresh();await api("news/"+channel+"/test","POST",{level:l});notice("TEST alert queued.","success");});testButton.disabled=!state.health.configured||(channel==="admin"&&l===2&&!state.health.policy.level_2_admin_user_id);actions.append(testButton);}c.append(actions);}root.append(c);
  }
  if(can("admin_news.configure")){const {routes}=await api("news-routing"),c=card("Routing matrix"),form=el("form"),tableWrap=el("div",undefined,"table-wrap"),t=el("table"),head=el("thead"),body=el("tbody"),inputs={};head.append(append(el("tr"),el("th","Event"),el("th","Classification"),el("th","Member News"),el("th","Admin News")));t.append(head,body);
    for(const r of routes){const tr=el("tr"),m=toggle(r.label+" → Member",!!r.member),a=toggle(r.label+" → Admin",!!r.admin);m.input.disabled=!r.member_allowed;m.wrap.classList.add("compact-toggle");a.wrap.classList.add("compact-toggle");append(tr,el("td",r.label),append(el("td"),badge(r.classification)),append(el("td"),m.wrap),append(el("td"),a.wrap));body.append(tr);inputs[r.event]={m:m.input,a:a.input};}
    tableWrap.append(t);const save=el("button","Apply routing");save.type="submit";form.append(tableWrap,el("p","Private event classifications are enforced by the backend and cannot be changed.","fine"),save);form.onsubmit=async e=>{e.preventDefault();try{await fresh();const values={};Object.entries(inputs).forEach(([name,v])=>{values[name]={member:v.m.checked,admin:v.a.checked};});await api("news-routing","PUT",{routes:values});notice("Routing validated and saved.","success");}catch(error){notice(error.message,"error");}};c.append(form);root.append(c);}root.classList.add("stack");return root;
};

async function accountSecurity(n){
  if(actor.must_change)n.append(el("p","You must change your password before using other tools.","callout"));
  if(actor.mfa_required&&!actor.mfa)n.append(el("p","Your account requires 2FA. Enroll below to unlock your assigned tools.","callout"));
  const form=el("form"),old=field("Current password","password"),next=field("New password · 10–256 characters","password"),repeat=field("Confirm new password","password"),otp=field("2FA or recovery code, if enrolled");
  old.input.autocomplete="current-password";next.input.autocomplete=repeat.input.autocomplete="new-password";
  for(const f of [old,next,repeat]){f.input.required=true;f.input.maxLength=256;}next.input.minLength=repeat.input.minLength=10;
  const submit=el("button","Change password");submit.type="submit";form.append(old.wrap,next.wrap,repeat.wrap,otp.wrap,submit);
  form.onsubmit=async e=>{e.preventDefault();if(next.input.value!==repeat.input.value){notice("New passwords do not match.","error");return;}try{await api("auth/password","POST",{current_password:old.input.value,new_password:next.input.value,otp:otp.input.value||null});form.reset();showLogin();notice("Password changed. All sessions revoked. Sign in with your new password.","success");}catch(error){notice(error.message,"error");}};
  const password=el("details",undefined,"accordion");password.append(el("summary","Change your password"),form);password.open=!!actor.must_change;n.append(password);
  if(!actor.mfa)n.append(button("Enroll TOTP 2FA",async()=>{await fresh();const result=await api("auth/totp/enroll","POST",{}),box=card("Add QSuite to your authenticator"),code=field("6-digit code");code.input.inputMode="numeric";code.input.maxLength=6;box.append(el("pre",result.uri),code.wrap,button("Confirm enrollment",async()=>{const data=await api("auth/totp/confirm","POST",{otp:code.input.value});box.replaceChildren(el("h2","Save recovery codes now"),el("pre",data.recovery_codes.join("\n")),el("p","Each code works once. Store these privately outside this server.","callout"));actor=await api("auth/me");box.append(button("Recovery codes saved · Continue",()=>showShell()));notice("2FA enabled. Save your recovery codes before navigating away.","success");}));n.append(box);}));
  const {sessions}=await api("auth/sessions"),sessionCard=card("Your active sessions");
  sessions.forEach(s=>{const r=row(date(s.created),"Seen "+date(s.last_seen));r.append(button("Revoke",async()=>{await fresh();await api("auth/sessions/"+s.identifier+"/revoke","POST",{});showShell().catch(()=>showLogin());}));sessionCard.append(r);});sessionCard.append(button("Revoke all my sessions",async()=>{if(!await confirmAction("Sign out everywhere","Revoke all your QSuite sessions, including this one?"))return;await fresh();await api("auth/sessions/revoke","POST",{});showLogin();}));n.append(sessionCard);
}
pages.settings=async()=>{
  const s=await api("settings"),n=card("Your account");n.append(row("Username",actor.username),row("Role",actor.role.replaceAll("_"," ")),row("2FA",actor.mfa?"Enabled":"Not enrolled"));await accountSecurity(n);
  if(s.access){const settings=card("Access & TLS");settings.append(row("Access",s.access.toUpperCase()),row("Origin",s.origin));const trust=toggle("Require trusted TLS for WAN",s.require_trusted_tls);trust.input.disabled=!can("access.configure")||actor.role!=="owner";trust.input.onchange=async()=>{const wanted=trust.input.checked;try{await fresh();await api("access/tls-policy","POST",{target:wanted?"required":"optional"});notice("TLS policy saved.","success");}catch(error){trust.input.checked=!wanted;notice(error.message,"error");}};settings.append(trust.wrap,el("p","HTTPS, secure cookies, identity checks and authentication are always required in production.","fine"));n.append(settings);}return n;
};

async function passwordReset(id,username){
  const dialog=el("dialog"),form=el("form"),password=field("New password for "+username,"password"),change=toggle("Require change after next sign-in",true),actions=el("div",undefined,"actions");password.input.autocomplete="new-password";password.input.required=true;password.input.minLength=10;password.input.maxLength=256;
  const cancel=button("Cancel",()=>{dialog.close();dialog.remove();}),submit=el("button","Reset password");submit.type="submit";actions.append(cancel,submit);form.append(el("h2","Set a new password"),el("p","This revokes the account's sessions. Existing 2FA is preserved.","muted"),password.wrap,change.wrap,actions);dialog.append(form);document.body.append(dialog);dialog.showModal();password.input.focus();
  form.onsubmit=async e=>{e.preventDefault();try{await fresh();await api("users/"+id+"/password","POST",{password:password.input.value,must_change:change.input.checked});form.reset();dialog.close();dialog.remove();notice("Password reset; sessions revoked.","success");render();}catch(error){notice(error.message,"error");}};dialog.oncancel=()=>dialog.remove();
}
pages.users=async()=>{
  const [{users},{roles,catalogue}]=await Promise.all([api("users"),api("roles")]),root=el("div"),c=card("Accounts & access");
  for(const u of users){const entry=el("details",undefined,"accordion"),summary=el("summary",u.username+" · "+u.role.replaceAll("_"," ")+" · "+(u.enabled?"Enabled":"Disabled"));entry.append(summary,row("Last login",date(u.last_login)),row("2FA",u.mfa?"Enabled":u.mfa_required?"Required, not enrolled":"Not enrolled"),row("Expires",u.expires?date(u.expires):"Never"));
    const actions=el("div",undefined,"actions");
    if(can("users.manage")){actions.append(button(u.enabled?"Disable":"Enable",async()=>{if(!await confirmAction("Change account access",(u.enabled?"Disable ":"Enable ")+u.username+" and revoke its sessions?"))return;await fresh();await api("users/"+u.id,"PATCH",{enabled:!u.enabled});notice("Account updated.","success");render();}),button("Reset password",()=>passwordReset(u.id,u.username)),button("Revoke sessions",async()=>{await fresh();await api("users/"+u.id+"/sessions/revoke","POST",{});notice("Sessions revoked.","success");}));
      const role=selectField("Role",roles.map(r=>[r.name,r.label]),u.role),required=toggle("Require 2FA",!!u.mfa_required),mustChange=toggle("Require password change",!!u.must_change),expiration=field("Expiration · blank for never","datetime-local",u.expires?new Date(u.expires*1000-new Date(u.expires*1000).getTimezoneOffset()*60000).toISOString().slice(0,16):"");entry.append(role.wrap,required.wrap,mustChange.wrap,expiration.wrap,button("Save account policy",async()=>{await fresh();await api("users/"+u.id,"PATCH",{role:role.input.value,mfa_required:required.input.checked,must_change:mustChange.input.checked,expires:expiration.input.value?Math.floor(new Date(expiration.input.value).getTime()/1000):null});notice("Account policy saved; sessions revoked.","success");render();}));
    }
    actions.append(button("Sessions & login history",async()=>{const [s,h]=await Promise.all([api("users/"+u.id+"/sessions"),api("users/"+u.id+"/history")]);const details=card("Session evidence");details.append(table(["Created","Seen","Expires","Source"],s.sessions.map(v=>[date(v.created),date(v.last_seen),date(v.expires),v.source])),...s.sessions.map(v=>button("Revoke session from "+v.source,async()=>{await fresh();await api("users/"+u.id+"/sessions/"+v.identifier+"/revoke","POST",{});notice("Session revoked.","success");})),table(["Time","Action","Result","Source"],h.history.map(v=>[date(v.ts),v.action,v.result,v.source])));entry.append(details);}));entry.append(actions);c.append(entry);
  }root.append(c);
  if(can("users.manage")){const n=card("Create account"),form=el("form"),username=field("Username"),password=field("Initial password · 10–256 characters","password"),role=selectField("Preset or custom role",roles.map(r=>[r.name,r.label]),"helper"),change=toggle("Require password change",true),mfa=toggle("Require 2FA",false);username.input.required=true;username.input.pattern="[a-zA-Z0-9_.-]{1,32}";password.input.required=true;password.input.minLength=10;password.input.maxLength=256;password.input.autocomplete="new-password";const submit=el("button","Create user");submit.type="submit";form.append(username.wrap,password.wrap,role.wrap,change.wrap,mfa.wrap,submit);form.onsubmit=async e=>{e.preventDefault();try{await fresh();await api("users","POST",{username:username.input.value,password:password.input.value,role:role.input.value,must_change:change.input.checked,mfa_required:mfa.input.checked});form.reset();notice("Account created.","success");render();}catch(error){notice(error.message,"error");}};n.append(form);root.append(n);}
  const matrix=card("Role permission matrix"),preset=el("details",undefined,"accordion");preset.append(el("summary","Inspect presets and custom roles"),table(["Role","Permissions"],roles.map(r=>[r.label,r.permissions.join(", ")])));matrix.append(preset);root.append(matrix);
  if(actor.role==="owner"){const policy=await api("authentication-policy"),n=card("Privileged account policy"),required=toggle("Require 2FA for roles with administrative permissions",policy.require_privileged_mfa);n.append(required.wrap,el("p","Accounts without enrolled 2FA retain access to Account settings for enrollment. Sensitive WAN operations always require 2FA.","fine"));required.input.onchange=async()=>{const wanted=required.input.checked;try{await fresh();await api("authentication-policy","PUT",{require_privileged_mfa:wanted});notice("Authentication policy saved.","success");}catch(error){required.input.checked=!wanted;notice(error.message,"error");}};root.append(n);}
  if(can("roles.manage")&&actor.role==="owner"){const n=card("Custom role editor"),form=el("form"),name=field("Role identifier · lowercase"),label=field("Display name"),chooser=selectField("Load a custom role",[["","New role"],...roles.filter(r=>!r.builtin).map(r=>[r.name,r.label])]),grid=el("div",undefined,"permission-grid"),checks={};name.input.pattern="[a-z][a-z0-9_-]{0,47}";name.input.required=label.input.required=true;for(const p of catalogue){checks[p]=toggle(p,false);grid.append(checks[p].wrap);}chooser.input.onchange=()=>{const r=roles.find(r=>r.name===chooser.input.value&&!r.builtin);name.input.value=r?.name||"";label.input.value=r?.label||"";for(const [p,f] of Object.entries(checks))f.input.checked=r?.permissions.includes(p)||false;};const submit=el("button","Save custom role");submit.type="submit";form.append(chooser.wrap,name.wrap,label.wrap,grid,submit);form.onsubmit=async e=>{e.preventDefault();try{await fresh();await api("roles/"+name.input.value,"PUT",{name:name.input.value,label:label.input.value,permissions:Object.keys(checks).filter(p=>checks[p].input.checked)});notice("Role saved. Assigned accounts' sessions were revoked.","success");render();}catch(error){notice(error.message,"error");}};n.append(form);root.append(n);}root.classList.add("stack");return root;
};
pages.audit=async()=>{const {audit}=await api("audit"),n=card("Administrative audit trail");n.append(el("p","Identifiers and outcomes only. Credentials and secret values are never recorded.","fine"),table(["Time","Actor","Action","Target","Result","Source"],audit.map(e=>[date(e.ts),e.user,e.action,e.object,e.result,e.source])));return n;};

let theme="dark";try{theme=localStorage.getItem("qsuite-theme")||"dark";}catch{/* Storage may be blocked by browser privacy settings. */}
document.documentElement.dataset.theme=theme==="light"?"light":"dark";
$("#theme").onclick=()=>{theme=document.documentElement.dataset.theme==="dark"?"light":"dark";document.documentElement.dataset.theme=theme;try{localStorage.setItem("qsuite-theme",theme);}catch{/* Theme is cosmetic; persistence is optional. */}};
showShell().catch(()=>showLogin());
