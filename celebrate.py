"""A one-time 'you're on the latest version' celebration page.

Shown once, in a foreground tab, the first time Vodou runs after its version
changes (an update — or the first launch of this feature). The page is fully
self-contained: inline CSS/JS, a <canvas> of falling confetti and fireworks,
and a congratulations message. It is rendered with setHtml (no file on disk,
no network) under the reserved sentinel host, so it never touches a real
origin.

The last version we celebrated is recorded in ~/.vodou/version.json, so the
page appears exactly once per update and never again for the same version.
"""

from __future__ import annotations

import json
from pathlib import Path

_SEEN_FILE = Path.home() / ".vodou" / "version.json"


def _seen() -> str:
    """The last version we showed the celebration for ('' if none / unreadable)."""
    try:
        data = json.loads(_SEEN_FILE.read_text(encoding="utf-8"))
        return str(data.get("seen", "")) if isinstance(data, dict) else ""
    except (OSError, ValueError):
        return ""


def due(current: str) -> bool:
    """True if the celebration should show — i.e. the running version differs
    from the last one we celebrated (a fresh install counts, since there is no
    prior version on record)."""
    return bool(current) and _seen() != current


def mark_seen(current: str) -> None:
    """Record `current` as celebrated, so the page won't show again for it."""
    try:
        _SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SEEN_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seen": current}), encoding="utf-8")
        tmp.replace(_SEEN_FILE)
    except OSError:
        pass


# The message is fixed and the version is Vodou's own APP_VERSION (not user
# input), so there is nothing to escape; the version is inserted by token
# replacement to avoid fighting the braces in the inline CSS/JS.
_PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>You're up to date 🎉</title>
<style>
  html,body{margin:0;height:100%;overflow:hidden;}
  body{background:radial-gradient(1200px 600px at 50% -12%,#151d42,#0b1026);}
  #sky{position:fixed;inset:0;display:block;}
  .card{position:fixed;inset:0;display:flex;flex-direction:column;
    align-items:center;justify-content:center;text-align:center;
    font-family:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
    color:#fff;pointer-events:none;padding:24px;box-sizing:border-box;}
  .emoji{font-size:64px;margin-bottom:10px;
    filter:drop-shadow(0 6px 16px rgba(0,0,0,.55));}
  h1{font-size:clamp(24px,5vw,44px);line-height:1.2;margin:0 0 14px;
    max-width:16em;font-weight:700;text-shadow:0 2px 18px rgba(0,0,0,.65);}
  p{font-size:clamp(14px,2.5vw,18px);margin:0;color:#c7d0f0;
    text-shadow:0 2px 10px rgba(0,0,0,.6);}
  .ver{margin-top:20px;font:600 13px/1 "Cascadia Mono",Consolas,monospace;
    color:#9fb0ee;background:rgba(255,255,255,.09);
    border:1px solid rgba(255,255,255,.14);padding:9px 15px;border-radius:999px;}
</style></head><body>
<canvas id="sky"></canvas>
<div class="card">
  <div class="emoji">🎉</div>
  <h1>Congratulations, you are running the latest version of Vodou!</h1>
  <p>Thanks for keeping your private browser up to date.</p>
  <div class="ver">v__VERSION__</div>
</div>
<script>
(function(){
  var c=document.getElementById('sky');
  if(!c||!c.getContext) return;
  var x=c.getContext('2d'),W,H;
  // Back the canvas at CSS resolution (1x), not devicePixelRatio: confetti and
  // fireworks don't need a retina buffer, and a smaller canvas keeps every
  // frame cheap so the animation stays smooth on a big / high-DPI display.
  function resize(){W=c.width=innerWidth;H=c.height=innerHeight;}
  resize(); addEventListener('resize',resize);
  var colors=['#ff5d73','#ffd166','#06d6a0','#4cc9f0','#b57bff','#ff9f1c','#ffffff'];
  function rnd(a,b){return a+Math.random()*(b-a);}
  function pick(a){return a[(Math.random()*a.length)|0];}

  var conf=[];
  function newPiece(spread){
    return {x:rnd(0,W), y:spread?rnd(-H,0):rnd(-40,0),
      w:rnd(6,12), h:rnd(8,16), vx:rnd(-0.9,0.9), vy:rnd(2.8,6.6),
      rot:rnd(0,Math.PI*2), vr:rnd(-0.3,0.3), col:pick(colors)};
  }
  for(var i=0;i<170;i++) conf.push(newPiece(true));

  var parts=[], last=0;
  function burst(px,py){
    var n=60+((Math.random()*40)|0), col=pick(colors);
    for(var i=0;i<n;i++){ var a=Math.random()*Math.PI*2, s=rnd(2,9);
      parts.push({x:px,y:py,vx:Math.cos(a)*s,vy:Math.sin(a)*s,life:1,col:col}); }
  }

  var t0=performance.now(), prev=t0;
  function frame(t){
    // Scale motion by the real time since the last frame (in 60fps units,
    // clamped), so speed is consistent and a hitched frame doesn't stutter.
    var dt=(t-prev)/16.667; if(!(dt>0))dt=1; if(dt>3)dt=3; prev=t;
    x.globalCompositeOperation='source-over';
    x.clearRect(0,0,W,H);
    for(var i=0;i<conf.length;i++){ var p=conf[i];
      p.x+=p.vx*dt; p.y+=p.vy*dt; p.vy+=0.03*dt; p.rot+=p.vr*dt;
      if(p.y>H+20){ conf[i]=newPiece(false); continue; }
      x.save(); x.translate(p.x,p.y); x.rotate(p.rot);
      x.fillStyle=p.col; x.fillRect(-p.w/2,-p.h/2,p.w,p.h); x.restore();
    }
    if(t-t0<30000 && t-last>rnd(350,650)){ last=t;
      burst(rnd(W*0.2,W*0.8), rnd(H*0.15,H*0.5)); }
    x.globalCompositeOperation='lighter';
    var decay=Math.pow(0.985,dt);
    for(var j=parts.length-1;j>=0;j--){ var q=parts[j];
      q.x+=q.vx*dt; q.y+=q.vy*dt; q.vy+=0.06*dt; q.vx*=decay; q.vy*=decay;
      q.life-=0.018*dt;
      if(q.life<=0){ parts.splice(j,1); continue; }
      x.globalAlpha=Math.max(q.life,0); x.fillStyle=q.col;
      x.beginPath(); x.arc(q.x,q.y,2.4,0,Math.PI*2); x.fill();
    }
    x.globalAlpha=1;
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
</script>
</body></html>"""


def html(version: str) -> str:
    """The self-contained celebration page for `version`."""
    return _PAGE.replace("__VERSION__", version)
