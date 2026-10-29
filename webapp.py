#!/usr/bin/env python3
"""Local web interface for phishing-email-analyzer (stdlib only).

Run:  python webapp.py          then open http://127.0.0.1:8000
Emails are analysed on your machine, written to a temp file, and deleted at once.
The server only listens on 127.0.0.1, so nobody else on your network can reach it.
"""
import argparse
import json
import os
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import analyzer

MAX_BYTES = 10 * 1024 * 1024

PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Phishing Email Analyzer</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{padding:28px 32px 8px;max-width:1100px;margin:0 auto}h1{margin:0;font-size:24px}
.sub{color:#8b949e;margin-top:4px}main{max-width:1100px;margin:0 auto;padding:16px 32px 48px}
#drop{border:2px dashed #30363d;border-radius:14px;padding:40px 20px;text-align:center;background:#161b22;cursor:pointer;transition:.15s}
#drop.over{border-color:#58a6ff;background:#1b2330}#drop b{font-size:17px}#drop p{margin:6px 0 0;color:#8b949e}
button{background:#238636;color:#fff;border:0;border-radius:8px;padding:8px 16px;font-size:14px;cursor:pointer;margin-top:14px}
#status{margin:14px 0;color:#8b949e;min-height:22px}#status.err{color:#ff7b72}
.grid{display:grid;grid-template-columns:260px 1fr;gap:18px;margin-top:8px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:0 0 10px}
#hist{list-style:none;margin:0;padding:0}#hist li{display:flex;justify-content:space-between;gap:8px;padding:8px;border-radius:8px;cursor:pointer;border-bottom:1px solid #21262d}
#hist li:hover,#hist li.sel{background:#1b2330}#hist span.n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-weight:700;font-size:12px;padding:2px 8px;border-radius:999px;white-space:nowrap}
.MALICIOUS{background:#da363433;color:#ff7b72}.SUSPICIOUS{background:#d2992233;color:#e3b341}.BENIGN{background:#23863633;color:#3fb950}
iframe{width:100%;height:880px;border:0;border-radius:12px;background:#0d1117}.empty{color:#6e7681;padding:30px;text-align:center}
</style></head><body>
<header><h1>Phishing Email Analyzer</h1><div class="sub">Drop an .eml file. It is analysed locally and never leaves your computer.</div></header>
<main>
<div id="drop"><b>Drop .eml files here</b><p>or click to choose (up to 10 MB each)</p>
<input id="file" type="file" accept=".eml,message/rfc822" multiple hidden></div>
<div id="status"></div>
<div class="grid"><div class="card"><h2>Analysed</h2><ul id="hist"></ul><div id="none" class="empty">Nothing yet</div></div>
<div class="card" style="padding:0"><iframe id="view" title="report" sandbox></iframe></div></div>
</main>
<script>
const drop=document.getElementById('drop'),input=document.getElementById('file'),
status=document.getElementById('status'),hist=document.getElementById('hist'),
view=document.getElementById('view'),none=document.getElementById('none');
const reports=[];
function tagClass(v){return v==='LIKELY BENIGN'?'BENIGN':v}
function show(i){view.srcdoc=reports[i].html;[...hist.children].forEach((li,j)=>li.classList.toggle('sel',j===i))}
async function send(file){
  status.className='';status.textContent='Analysing '+file.name+' ...';
  try{
    const r=await fetch('/analyze?name='+encodeURIComponent(file.name),{method:'POST',body:file});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Failed');
    reports.push(d);none.style.display='none';
    const li=document.createElement('li');
    const n=document.createElement('span');n.className='n';n.textContent=d.name;
    const t=document.createElement('span');t.className='tag '+tagClass(d.verdict);t.textContent=d.score;
    li.append(n,t);const idx=reports.length-1;li.onclick=()=>show(idx);hist.append(li);show(idx);
    status.textContent='Done: '+d.name+' scored '+d.score+'/100 ('+d.verdict+')';
  }catch(e){status.className='err';status.textContent='Error: '+e.message}
}
async function many(files){for(const f of files)await send(f)}
drop.onclick=()=>input.click();input.onchange=()=>many(input.files);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('over')}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('over')}));
drop.addEventListener('drop',ev=>many(ev.dataTransfer.files));
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?")[0] == "/":
            self._send(200, PAGE, "text/html")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path.split("?")[0] != "/analyze":
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size <= 0 or size > MAX_BYTES:
            return self._send(400, json.dumps({"error": "File is empty or larger than 10 MB"}))
        raw = self.rfile.read(size)
        qs = parse_qs(urlparse(self.path).query)
        name = os.path.basename((qs.get("name") or ["email.eml"])[0])[:80] or "email.eml"
        tmp = tempfile.NamedTemporaryFile(suffix=".eml", delete=False)
        try:
            tmp.write(raw)
            tmp.close()
            report = analyzer.analyze(tmp.name)
        except Exception as exc:
            return self._send(422, json.dumps({"error": f"Could not analyse this file: {type(exc).__name__}"}))
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        report["file"] = name
        self._send(200, json.dumps({"name": name, "score": report["score"],
                                    "verdict": report["verdict"],
                                    "html": analyzer.render_html(report)}))

    def log_message(self, fmt, *args):
        pass  # do not print file names to the terminal


def make_server(port=8000):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    ap = argparse.ArgumentParser(description="Local web UI for phishing-email-analyzer")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    srv = make_server(a.port)
    print(f"Open http://127.0.0.1:{a.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
