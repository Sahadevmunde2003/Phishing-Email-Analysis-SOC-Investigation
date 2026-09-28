async function analyze(){
  const file=document.getElementById("file").files[0];
  if(!file){document.getElementById("status").textContent="Select an .eml file first.";return;}
  const fd=new FormData(); fd.append("email",file);
  const r=await fetch("/analyze",{method:"POST",body:fd}); const d=await r.json();
  if(!r.ok){document.getElementById("status").textContent=d.error;return;} renderResult(d);
}
async function report(){
  const file=document.getElementById("file").files[0];
  if(!file){document.getElementById("status").textContent="Select an .eml file first.";return;}
  const fd=new FormData();fd.append("email",file); const r=await fetch("/report",{method:"POST",body:fd});
  const blob=await r.blob(); const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="phishing_analysis_report.html";a.click();
}
async function analyzeRaw(){const raw=document.getElementById("rawEmail").value.trim();if(!raw){document.getElementById("status").textContent="Paste the raw email first.";return;}const r=await fetch("/analyze-raw",{method:"POST",headers:{"Content-Type":"text/plain"},body:raw});const d=await r.json();if(!r.ok){document.getElementById("status").textContent=d.error;return;}renderResult(d);}
async function reportRaw(){const raw=document.getElementById("rawEmail").value.trim();if(!raw){document.getElementById("status").textContent="Paste the raw email first.";return;}const r=await fetch("/report-raw",{method:"POST",headers:{"Content-Type":"text/plain"},body:raw});const blob=await r.blob();const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="phishing_analysis_report.html";a.click();}
function renderResult(d){document.getElementById("status").textContent="Analysis complete.";document.getElementById("dashboard").classList.remove("hidden");document.getElementById("score").textContent=d.score+"/100";document.getElementById("severity").textContent=d.severity;document.getElementById("urlCount").textContent=d.urls.length;document.getElementById("attCount").textContent=d.attachments.length;document.getElementById("subject").textContent=d.subject||"(none)";document.getElementById("from").textContent=d.from||"(none)";document.getElementById("reply").textContent=d.reply_to||"(none)";document.getElementById("findings").innerHTML=d.findings.length?d.findings.map(f=>`<div class="finding"><b>[${f.severity}] ${escapeHtml(f.title)}</b><br>${escapeHtml(f.detail)}</div>`).join(""):"No heuristic findings.";document.getElementById("iocs").innerHTML="<b>URLs</b>"+d.iocs.urls.map(x=>`<div class="ioc">${escapeHtml(x)}</div>`).join("")+"<br><b>Domains</b>"+d.iocs.domains.map(x=>`<div class="ioc">${escapeHtml(x)}</div>`).join("")+"<br><b>Attachments</b>"+d.iocs.attachments.map(x=>`<div>${escapeHtml(x)}</div>`).join("");document.getElementById("mitre").innerHTML=d.mitre_attack.length?d.mitre_attack.map(x=>`<p><b>${x.id}</b> — ${escapeHtml(x.name)}</p>`).join(""):"No mappings.";document.getElementById("recommendations").innerHTML=d.recommendations.map(x=>`<li>${escapeHtml(x)}</li>`).join("");}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));}
