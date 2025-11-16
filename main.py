# main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import sqlite3
import datetime
import uvicorn
import os
import httpx
from urllib.parse import urlparse
import validators

# ---------------- Config ----------------
DB_FILE = "proxy_app.db"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # set this in your environment to enable AI classification
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"

# Domains that must never be auto-blocked by this service
NO_BLOCK_ENV = os.getenv("NO_BLOCK_DOMAINS", "web-blocker.onrender.com,localhost,127.0.0.1")
NO_BLOCK_DOMAINS = {d.strip().lower() for d in NO_BLOCK_ENV.split(",") if d.strip()}

# ---------------- App ----------------
app = FastAPI(title="Proxy Management API with AI Blocking (whitelist-safe)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB Setup ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Users
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    # Blocked sites
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT UNIQUE
        )
    """)
    # Logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            status TEXT,
            timestamp TEXT
        )
    """)
    # Migration: add 'reason' column if missing
    try:
        c.execute("ALTER TABLE logs ADD COLUMN reason TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()

init_db()

# ---------------- Models ----------------
class User(BaseModel):
    email: str
    password: str

class Site(BaseModel):
    domain: str

class LogEntry(BaseModel):
    domain: str
    status: str  # "ALLOWED" or "BLOCKED"
    timestamp: str = None
    reason: str = None

class DomainRequest(BaseModel):
    domain: str

# ---------------- Utilities ----------------
def normalize_domain(domain: str) -> str:
    """Normalize domain (strip protocol, www, trailing slash)."""
    if not domain:
        return domain
    try:
        parsed = urlparse(domain if domain.startswith("http") else f"http://{domain}")
        domain_norm = parsed.netloc or parsed.path
        domain_norm = domain_norm.lower().replace("www.", "").rstrip("/")
        return domain_norm
    except Exception:
        return domain.lower().strip()

def is_valid_domain(domain: str) -> bool:
    """Validate domain with validators library."""
    try:
        return bool(domain) and validators.domain(domain)
    except Exception:
        return False

def in_no_block_list(domain: str) -> bool:
    """Return True if domain matches any NO_BLOCK_DOMAINS entry (substring match)."""
    d = domain.lower()
    for nb in NO_BLOCK_DOMAINS:
        if not nb:
            continue
        if nb == d or d.endswith("." + nb):
            return True
    return False

def add_blocked_site(domain: str):
    """Insert domain into blocked_sites table (idempotent)."""
    domain = normalize_domain(domain)
    if not domain:
        return
    if in_no_block_list(domain):
        print(f"[INFO] Skipping adding whitelisted domain to blocked_sites: {domain}")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_sites (site) VALUES (?)", (domain,))
        conn.commit()
        print(f"[INFO] Added to blocked_sites: {domain}")
    except sqlite3.IntegrityError:
        pass  # already exists
    finally:
        conn.close()

def log_site(domain: str, status: str, reason: str = None):
    """Add a log entry for domain status."""
    ts = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (domain, status, reason, timestamp) VALUES (?, ?, ?, ?)",
        (domain, status, reason or "", ts)
    )
    conn.commit()
    conn.close()

# ---------------- Local fallback lists ----------------
AI_TOOLS = {"chat.openai.com", "openai.com", "huggingface.co", "bard.google.com", "runwayml.com",
            "perplexity.ai", "midjourney.com", "stability.ai", "replit.com", "notion.ai",
            "copy.ai", "jasper.ai", "writesonic.com", "you.com", "ai21.com"}

GAMBLING_SITES = {"betway.co.za", "sportingbet.co.za", "bet.co.za", "worldbetting.co.za", "betsafe.co.za",
                  "bet365.com", "1xbet.com", "pinnacle.com"}

PORN_SITES_SAMPLE = {"xnxx.com", "xvideos.com", "pornhub.com", "xhamster.com", "redtube.com"}

MALICIOUS_SAMPLE = {"malware.example", "badsite.example"}

QUICK_CHECK_MAP = {}
for d in AI_TOOLS:
    QUICK_CHECK_MAP[d] = "ai tool"
for d in GAMBLING_SITES:
    QUICK_CHECK_MAP[d] = "gambling"
for d in PORN_SITES_SAMPLE:
    QUICK_CHECK_MAP[d] = "adult"
for d in MALICIOUS_SAMPLE:
    QUICK_CHECK_MAP[d] = "malicious"

# ---------------- Endpoints ----------------
@app.post("/register")
def register(user: User):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (user.email, user.password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    conn.close()
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: User):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=? AND password=?", (user.email, user.password))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"message": "Login successful"}

@app.post("/block-site")
def block_site(site: Site):
    domain = normalize_domain(site.domain)
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")
    add_blocked_site(domain)
    return {"message": f"Site '{domain}' blocked successfully"}

@app.get("/blocked-sites", response_model=List[str])
def get_blocked_sites():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT site FROM blocked_sites")
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

@app.delete("/blocked-sites/{domain}")
def delete_blocked_site(domain: str):
    domain = normalize_domain(domain)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_sites WHERE site=?", (domain,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Site '{domain}' not found in blocked list")
    c.execute("DELETE FROM blocked_sites WHERE site=?", (domain,))
    conn.commit()
    conn.close()
    return {"message": f"Site '{domain}' has been removed from blocked sites"}

@app.post("/logs")
async def receive_log(log: LogEntry):
    ts = log.timestamp or datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (domain, status, reason, timestamp) VALUES (?, ?, ?, ?)",
        (log.domain, log.status, log.reason or "", ts)
    )
    conn.commit()
    conn.close()
    return {"message": "Log received"}

@app.get("/logs", response_model=List[LogEntry])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain, status, reason, timestamp FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"domain": r[0], "status": r[1], "reason": r[2], "timestamp": r[3]} for r in rows]

@app.get("/")
def root():
    return {"message": "Proxy Management API is running (whitelist-safe)"}

# ---------------- AI Analysis endpoint ----------------
@app.post("/analyze-domain")
async def analyze_domain(req: DomainRequest):
    domain_raw = req.domain
    domain = normalize_domain(domain_raw)

    if not domain or not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    if in_no_block_list(domain):
        log_site(domain, "ALLOWED", "whitelisted")
        return {"unwanted": False, "reason": "whitelisted"}

    # Quick local checks
    for k, reason in QUICK_CHECK_MAP.items():
        if k in domain:
            add_blocked_site(domain)
            log_site(domain, "BLOCKED", reason)
            return {"unwanted": True, "reason": reason}

    if not GROQ_API_KEY:
        log_site(domain, "ALLOWED", "no_api_key")
        return {"unwanted": False, "reason": "no_api_key"}

    system_prompt = (
        "You are a classifier. Answer in a single short sentence or word: 'Yes' or 'No'. "
        "You must only judge whether the domain is unwanted for general users because it belongs to one of these categories: "
        "gambling/betting, porn/adult, unsafe/malicious, or AI tools. "
        "If 'Yes', follow with a short category keyword in parentheses — e.g. 'Yes (gambling)'."
    )
    user_prompt = (
        f"Is the domain '{domain}' unwanted for general users because it is gambling, streaming of pirated content, porn/adult, malicious, or an AI tool? "
        "Answer exactly like 'Yes (category)' or 'No'. Categories: gambling, streaming, porn, malicious, ai_tool."
    )

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 12,
        "temperature": 0.0,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()
            data = res.json()

            answer_text = ""
            if isinstance(data, dict):
                choices = data.get("choices") or []
                if choices:
                    msg = choices[0].get("message") or {}
                    answer_text = (msg.get("content") or "").strip()
                else:
                    answer_text = (data.get("text") or "").strip()

            answer_lc = (answer_text or "").lower()
            unwanted = False
            reason = None

            if answer_lc.startswith("yes"):
                unwanted = True
                if "(" in answer_text and ")" in answer_text:
                    reason = answer_text.split("(", 1)[1].split(")", 1)[0].strip()
                else:
                    for kw in ["gambling", "betting", "porn", "adult", "streaming", "malicious", "ai", "ai_tool"]:
                        if kw in answer_lc:
                            reason = kw
                            break
                    if not reason:
                        reason = "unwanted"
            else:
                unwanted = False
                reason = "allowed"

            if unwanted:
                if in_no_block_list(domain):
                    log_site(domain, "ALLOWED", "whitelisted")
                    return {"unwanted": False, "reason": "whitelisted"}
                add_blocked_site(domain)
                log_site(domain, "BLOCKED", reason)
            else:
                log_site(domain, "ALLOWED", reason)

            return {"unwanted": unwanted, "reason": reason, "model_answer": answer_text}

    except Exception as e:
        print(f"[WARNING] AI analyze failed for {domain}: {e}")
        log_site(domain, "ALLOWED", "ai_error")
        return {"unwanted": False, "reason": "ai_error"}

# ---------------- Run ----------------
if __name__ == "__main__":
    print(f"[INFO] NO_BLOCK_DOMAINS = {NO_BLOCK_DOMAINS}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
