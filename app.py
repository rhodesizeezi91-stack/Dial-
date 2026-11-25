"""AI dialer: dials numbers.csv in order, an AI agent talks to whoever answers,
and the dashboard lists connected calls so you can transfer them to your phone."""
import asyncio, csv, hashlib, hmac, os, re, time
from pathlib import Path

from anthropic import Anthropic
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from twilio.request_validator import RequestValidator
from twilio.rest import Client
from twilio.twiml.voice_response import Gather, VoiceResponse

load_dotenv()
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")
FROM_NUMBER = os.environ["TWILIO_FROM_NUMBER"]
TRANSFER_TO = os.environ["TRANSFER_TO_NUMBER"]
MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")
BUSINESS = os.getenv("BUSINESS_NAME", "our company")
NUMBERS_FILE = Path(os.getenv("NUMBERS_FILE", "numbers.csv"))
MAX_SECONDS = int(os.getenv("MAX_CALL_SECONDS", "300"))
DNC_FILE = Path(os.getenv("DNC_FILE", "dnc.txt"))
STOP_PHRASES = ("stop calling", "remove me", "do not call", "don't call",
                "take me off", "unsubscribe", "remove my number")

# ---- Edit this: who the agent is and what it says -------------------------
SYSTEM_PROMPT = f"""You are a friendly AI phone assistant calling on behalf of {BUSINESS}.
Goal: briefly find out if the person is interested in talking to a team member.
Rules:
- You are on a live phone call. Reply in 1-2 short spoken sentences. No lists, no markdown.
- Never claim to be human. If asked, say you're an AI assistant.
- If they want to talk to a person or are interested, reply warmly and end with [HUMAN].
- If they're not interested or the conversation is over, say a polite goodbye and end with [END].
- Never invent facts about the company, pricing, or promises."""
# ----------------------------------------------------------------------------

twilio = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])
claude = Anthropic()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# ---- Dashboard login ------------------------------------------------------
# Change the password by editing DASHBOARD_PASSWORD and restarting the app.
# Changing it also logs out every existing session.
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
if len(PASSWORD) < 8:
    raise SystemExit("Set DASHBOARD_PASSWORD (at least 8 characters).")
SESSION_KEY = hashlib.sha256(("dialer-session:" + PASSWORD).encode()).digest()
SESSION_HOURS = 12
SECURE_COOKIE = PUBLIC_URL.startswith("https")
fails: dict[str, list[float]] = {}

LOGIN_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Dialer login</title>
<style>
:root{--bg:#e8ece9;--panel:#f6f8f6;--ink:#17282a;--mute:#5c6d6b;--line:#c9d2cd;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#101a1b;--panel:#182527;--ink:#e6efec;--mute:#8da09d;--line:#2a3b3d;--err:#ff8a80}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px system-ui,sans-serif;padding:16px}
form{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:24px;width:100%;max-width:340px}
h1{font-size:20px;margin:0 0 16px}label{display:block;color:var(--mute);margin-bottom:6px}
input{width:100%;font:inherit;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
button{width:100%;margin-top:14px;font:inherit;font-weight:600;border:0;border-radius:6px;padding:10px;background:var(--ink);color:var(--panel);cursor:pointer}
.err{color:var(--err);margin:12px 0 0;min-height:1em}
</style></head><body>
<form method="post" action="/login"><h1>AI Dialer</h1>
<label for="p">Password</label>
<input id="p" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">Log in</button><p class="err">__ERROR__</p></form></body></html>"""


def make_token() -> str:
    exp = str(int(time.time()) + SESSION_HOURS * 3600)
    return exp + "." + hmac.new(SESSION_KEY, exp.encode(), "sha256").hexdigest()


def valid_token(tok: str) -> bool:
    try:
        exp, sig = tok.split(".")
        good = hmac.new(SESSION_KEY, exp.encode(), "sha256").hexdigest()
        return hmac.compare_digest(sig, good) and int(exp) > time.time()
    except Exception:
        return False


@app.middleware("http")
async def require_login(request: Request, call_next):
    p = request.url.path
    if (p == "/" or p.startswith("/api/")) and not valid_token(request.cookies.get("session", "")):
        if p.startswith("/api/"):
            return JSONResponse({"error": "login required"}, status_code=401)
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return LOGIN_HTML.replace("__ERROR__", "")


@app.post("/login")
async def login(request: Request, password: str = Form("")):
    fwd = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
    ip = fwd or (request.client.host if request.client else "?")
    now = time.time()
    recent = [t for t in fails.get(ip, []) if now - t < 600]
    if len(recent) >= 5:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", "Too many attempts. Wait 10 minutes."), status_code=429)
    if hmac.compare_digest(password.encode(), PASSWORD.encode()):
        fails.pop(ip, None)
        r = RedirectResponse("/", status_code=303)
        r.set_cookie("session", make_token(), max_age=SESSION_HOURS * 3600,
                     httponly=True, samesite="lax", secure=SECURE_COOKIE)
        return r
    fails[ip] = recent + [now]
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", "Wrong password."), status_code=401)


@app.get("/logout")
async def logout():
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie("session")
    return r


# ---- Only accept webhooks that really come from Twilio --------------------
validator = RequestValidator(os.environ["TWILIO_AUTH_TOKEN"])


async def verify_twilio(request: Request):
    form = await request.form()
    sig = request.headers.get("X-Twilio-Signature", "")
    if not validator.validate(PUBLIC_URL + request.url.path, dict(form), sig):
        raise HTTPException(status_code=403, detail="bad signature")

calls: dict[str, dict] = {}          # CallSid -> call record
done: dict[str, asyncio.Event] = {}  # CallSid -> set when dialer may move on
state = {"running": False, "index": 0, "total": 0}
task: asyncio.Task | None = None


def clean(n: str) -> str:
    return re.sub(r"[^\d+]", "", n)


def load_numbers():
    rows = []
    with NUMBERS_FILE.open(newline="") as f:
        for r in csv.reader(f):
            if not r or not r[0].strip():
                continue
            num = clean(r[0])
            if not re.match(r"^\+?\d{7,15}$", num):
                continue  # header or junk line
            rows.append((num, r[1].strip() if len(r) > 1 else ""))
    return rows


def load_dnc():
    return set(DNC_FILE.read_text().split()) if DNC_FILE.exists() else set()


def xml(vr: VoiceResponse) -> Response:
    return Response(str(vr), media_type="application/xml")


def listen(text: str) -> VoiceResponse:
    vr = VoiceResponse()
    g = Gather(input="speech", action=f"{PUBLIC_URL}/voice/turn", method="POST",
               speech_timeout="auto", timeout=6)
    g.say(text)
    vr.append(g)
    vr.redirect(f"{PUBLIC_URL}/voice/turn", method="POST")  # silence -> empty turn
    return vr


def ask_claude(c: dict) -> str:
    msgs = [{"role": "user", "content": "(The call just connected; the person answered.)"}]
    for who, text in c["transcript"]:
        msgs.append({"role": "assistant" if who == "ai" else "user", "content": text})
    r = claude.messages.create(model=MODEL, max_tokens=200, system=SYSTEM_PROMPT, messages=msgs)
    return r.content[0].text.strip()


# ---- Dialer loop: one call at a time, in file order -----------------------
async def dial_loop():
    rows, dnc = load_numbers(), load_dnc()
    state.update(total=len(rows), index=0)
    for i, (number, name) in enumerate(rows, 1):
        if not state["running"]:
            break
        state["index"] = i
        if number in dnc:
            continue
        try:
            call = await asyncio.to_thread(
                twilio.calls.create, to=number, from_=FROM_NUMBER,
                url=f"{PUBLIC_URL}/voice/answer", method="POST",
                status_callback=f"{PUBLIC_URL}/voice/status", status_callback_method="POST",
                status_callback_event=["ringing", "completed"],
                machine_detection="Enable", time_limit=MAX_SECONDS)
        except Exception as e:
            calls[f"err-{i}"] = dict(sid=f"err-{i}", number=number, name=name,
                                      status=f"error: {e}"[:80], transcript=[], ended=time.time())
            continue
        calls[call.sid] = dict(sid=call.sid, number=number, name=name, status="dialing",
                               transcript=[], wants_human=False, silence=0, hold=0,
                               started=time.time(), answered=None, ended=None)
        done[call.sid] = asyncio.Event()
        try:
            await asyncio.wait_for(done[call.sid].wait(), MAX_SECONDS + 60)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(2)
    state["running"] = False


# ---- Twilio webhooks ------------------------------------------------------
@app.post("/voice/answer", dependencies=[Depends(verify_twilio)])
async def answer(CallSid: str = Form(...), AnsweredBy: str = Form("unknown")):
    c, vr = calls[CallSid], VoiceResponse()
    if AnsweredBy.startswith("machine") or AnsweredBy == "fax":
        c["status"] = "voicemail"
        vr.hangup()
        return xml(vr)
    c["status"], c["answered"] = "connected", time.time()
    hi = f"Hi{' ' + c['name'] if c['name'] else ''}, this is an automated assistant calling " \
         f"on behalf of {BUSINESS}. Do you have a quick minute?"
    c["transcript"].append(("ai", hi))
    return xml(listen(hi))


@app.post("/voice/turn", dependencies=[Depends(verify_twilio)])
async def turn(CallSid: str = Form(...), SpeechResult: str = Form("")):
    c, vr = calls[CallSid], VoiceResponse()
    speech = SpeechResult.strip()
    if not speech:
        c["silence"] += 1
        if c["silence"] >= 2:
            vr.say("Sorry I missed you. Goodbye.")
            vr.hangup()
            return xml(vr)
        return xml(listen("Sorry, I didn't catch that. Are you still there?"))
    c["silence"] = 0
    c["transcript"].append(("them", speech))

    if any(p in speech.lower() for p in STOP_PHRASES):
        DNC_FILE.open("a").write(c["number"] + "\n")
        c["status"] = "opted_out"
        vr.say("Understood. We'll remove your number. Goodbye.")
        vr.hangup()
        return xml(vr)

    reply = await asyncio.to_thread(ask_claude, c)
    human, end = "[HUMAN]" in reply, "[END]" in reply
    reply = reply.replace("[HUMAN]", "").replace("[END]", "").strip()
    c["transcript"].append(("ai", reply))

    if end:
        vr.say(reply)
        vr.hangup()
    elif human:
        c["wants_human"] = True
        vr.say(reply + " Please hold for just a moment.")
        vr.redirect(f"{PUBLIC_URL}/voice/hold", method="POST")
    else:
        return xml(listen(reply))
    return xml(vr)


@app.post("/voice/hold", dependencies=[Depends(verify_twilio)])
async def hold(CallSid: str = Form(...)):
    c, vr = calls[CallSid], VoiceResponse()
    c["hold"] += 1
    if c["hold"] > 4:
        vr.say("Sorry, nobody is available right now. We'll follow up. Goodbye.")
        vr.hangup()
        return xml(vr)
    vr.pause(length=15)
    vr.say("Thanks for holding.")
    vr.redirect(f"{PUBLIC_URL}/voice/hold", method="POST")
    return xml(vr)


@app.post("/voice/status", dependencies=[Depends(verify_twilio)])
async def status(CallSid: str = Form(...), CallStatus: str = Form(...)):
    c = calls.get(CallSid)
    if not c:
        return Response(status_code=204)
    if CallStatus == "ringing":
        c["status"] = "ringing"
    elif CallStatus in ("completed", "busy", "no-answer", "failed", "canceled"):
        if c["status"] not in ("voicemail", "transferred", "opted_out"):
            c["status"] = "completed" if c["answered"] else CallStatus
        c["ended"] = time.time()
        if CallSid in done:
            done[CallSid].set()
    return Response(status_code=204)


# ---- Dashboard API --------------------------------------------------------
def view(c):
    end = c["ended"] or time.time()
    return dict(sid=c["sid"], number=c["number"], name=c["name"], status=c["status"],
                wants_human=c.get("wants_human", False), transcript=c["transcript"][-6:],
                seconds=int(end - c["answered"]) if c.get("answered") else 0)


@app.get("/api/state")
async def api_state():
    live = [view(c) for c in calls.values() if c["status"] == "connected" and not c["ended"]]
    past = [view(c) for c in calls.values() if c["ended"] or c["status"] not in ("dialing", "ringing", "connected")]
    return dict(running=state["running"], index=state["index"], total=state["total"],
                connected=live, finished=past[-25:][::-1])


@app.post("/api/start")
async def api_start():
    global task
    if not state["running"]:
        state["running"] = True
        task = asyncio.create_task(dial_loop())
    return {"ok": True}


@app.post("/api/stop")
async def api_stop():
    state["running"] = False
    return {"ok": True}


@app.post("/api/transfer/{sid}")
async def api_transfer(sid: str):
    c = calls.get(sid)
    if not c or c["status"] != "connected":
        return {"ok": False, "error": "call is not connected"}
    twiml = f"<Response><Say>Connecting you now.</Say><Dial>{TRANSFER_TO}</Dial></Response>"
    await asyncio.to_thread(twilio.calls(sid).update, twiml=twiml)
    c["status"] = "transferred"
    if sid in done:
        done[sid].set()  # free the dialer to continue while you talk
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def index():
    return Path(__file__).with_name("dashboard.html").read_text()
