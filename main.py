from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import datetime
import uvicorn
import os
import httpx
from urllib.parse import urlparse
import validators
from bs4 import BeautifulSoup
import routes

app = FastAPI()

# ---------------- Config ----------------
DB_FILE = "proxy_app.db"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # set to enable AI classification
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"

# Domains that must never be auto-blocked by this service (comma-separated env var)
NO_BLOCK_ENV = os.getenv("NO_BLOCK_DOMAINS", "web-blocker.onrender.com,localhost,127.0.0.1")
NO_BLOCK_DOMAINS = {d.strip().lower() for d in NO_BLOCK_ENV.split(",") if d.strip()}

# ---------------- App ----------------
app = FastAPI(title="Proxy Management API with AI Blocking (whitelist-safe)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB Setup (with migration) ----------------
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
    # Logs - initial columns
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
        # column exists already
        pass
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
    timestamp: Optional[str] = None
    reason: Optional[str] = None

class DomainRequest(BaseModel):
    domain: str

# ---------------- Utilities ----------------
def normalize_domain(domain: str) -> str:
    """Return normalized domain (no scheme, no www, lowercase)."""
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
    """Validate domain using validators.domain (returns bool)."""
    try:
        return bool(domain) and validators.domain(domain)
    except Exception:
        return False

def in_no_block_list(domain: str) -> bool:
    """True if domain equals or is subdomain of any entry in NO_BLOCK_DOMAINS."""
    d = domain.lower()
    for nb in NO_BLOCK_DOMAINS:
        if not nb:
            continue
        if d == nb or d.endswith("." + nb):
            return True
    return False

def add_blocked_site(domain: str):
    """Add domain to blocked_sites (idempotent)."""
    domain = normalize_domain(domain)
    if not domain:
        return
    if in_no_block_list(domain):
        print(f"[INFO] Not blocking whitelisted domain: {domain}")
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_sites (site) VALUES (?)", (domain,))
        conn.commit()
        print(f"[INFO] Added blocked site: {domain}")
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def log_site(domain: str, status: str, reason: Optional[str] = None):
    """Insert a log entry (always include reason column)."""
    ts = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (domain, status, reason, timestamp) VALUES (?, ?, ?, ?)",
              (domain, status, reason or "", ts))
    conn.commit()
    conn.close()

# ---------------- Local rule lists ----------------
SOCIAL_MEDIA = {"facebook", "instagram", "tiktok", "snapchat", "twitter", "x.com", "weibo", "linkedin", "pinterest"}
AI_TOOL_SITES = {"chatgpt", "openai", "bard.google", "huggingface", "deepseek", "claude", "anthropic",
                 "perplexity", "replit", "copilot", "notion.ai", "jasper", "copy.ai", "writesonic"}
STREAMING_SITES = {"netflix", "primevideo", "hulu", "disneyplus", "twitch", "showmax", "fmovies", "123movies", "putlocker", "soap2day", "gomovies"}
ADULT_SITES = {"porn", "xvideos", "xnxx", "redtube", "xhamster", "pornhub", "brazzers"}
GAMBLING_SITES = {"betway", "bet365", "hollywoodbets", "sportingbet", "1xbet", "pinnacle", "betsafe"}
MALICIOUS_KEYWORDS = {"malware", "phish", "scam", "ransom", "crypto-steal", "exploit", "trojan"}
EDUCATIONAL_KEYWORDS = {"edu", "wikipedia", "scholar", "khanacademy", "coursera", "edx", "udemy", "moodle", "blackboard",
                        "stackoverflow", "w3schools", "geeksforgeeks", "microsoftlearn", "kaggle", "research", "springer", "ieee"}

# Build quick-check map
QUICK_CHECK_MAP = {}
for d in SOCIAL_MEDIA: QUICK_CHECK_MAP[d] = "social_media"
for d in AI_TOOL_SITES: QUICK_CHECK_MAP[d] = "ai_tool"
for d in STREAMING_SITES: QUICK_CHECK_MAP[d] = "streaming"
for d in ADULT_SITES: QUICK_CHECK_MAP[d] = "adult"
for d in GAMBLING_SITES: QUICK_CHECK_MAP[d] = "gambling"
for d in MALICIOUS_KEYWORDS: QUICK_CHECK_MAP[d] = "malicious"
for d in EDUCATIONAL_KEYWORDS: QUICK_CHECK_MAP[d] = "educational"

# ---------------- Helper: quick check ----------------
def quick_classify(domain: str):
    d = domain.lower()
    if in_no_block_list(d):
        return False, "whitelisted"
    for k in EDUCATIONAL_KEYWORDS:
        if k in d:
            return False, "educational"
    for k, reason in QUICK_CHECK_MAP.items():
        if k in d and reason != "educational":
            return True, reason
    return None, None

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

app.include_router(routes.router)

@app.post("/logs")
async def receive_log(log: LogEntry):
    ts = log.timestamp or datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (domain, status, reason, timestamp) VALUES (?, ?, ?, ?)",
              (log.domain, log.status, log.reason or "", ts))
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

# ---------------- AI Analysis with HTML ----------------
@app.post("/analyze-domain")
async def analyze_domain(req: DomainRequest):
    domain_raw = req.domain
    domain = normalize_domain(domain_raw)

    if not domain or not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    quick = quick_classify(domain)
    if quick != (None, None):
        unwanted, reason = quick
        if unwanted:
            if in_no_block_list(domain):
                log_site(domain, "ALLOWED", "whitelisted")
                return {"unwanted": False, "reason": "whitelisted"}
            add_blocked_site(domain)
            log_site(domain, "BLOCKED", reason)
            return {"unwanted": True, "reason": reason}
        else:
            log_site(domain, "ALLOWED", reason)
            return {"unwanted": False, "reason": reason}

    if not GROQ_API_KEY:
        log_site(domain, "ALLOWED", "no_api_key")
        return {"unwanted": False, "reason": "no_api_key"}

    # Fetch HTML content
    site_text = ""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"http://{domain}"
            res = await client.get(url)
            res.raise_for_status()
            soup = BeautifulSoup(res.text, "html.parser")
            site_text = ' '.join(soup.stripped_strings)
            site_text = site_text[:5000]
    except Exception as e:
        print(f"[WARNING] Failed to fetch HTML for {domain}: {e}")
        site_text = ""

    # Prepare AI prompt
    system_prompt = (
        "You are a classifier that answers with either 'Yes (category)' or 'No'. "
        "Categories: gambling, streaming, porn, malicious, ai_tool, social_media, distracting. "
        "Only decide if the domain is UNWANTED for general users (not educational)."
    )
    user_prompt = (
        f"Domain: '{domain}'\nHTML text: '{site_text}'\n"
        "Is this site unwanted for general users because it is gambling, illegal streaming, porn/adult, malicious, an AI tool, social media, or distracting? "
        "Answer exactly 'Yes (category)' or 'No'."
    )

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 50,
        "temperature": 0.0,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()
            data = res.json()

            model_answer = ""
            if isinstance(data, dict):
                choices = data.get("choices") or []
                if choices and isinstance(choices, list) and choices[0].get("message"):
                    model_answer = (choices[0]["message"].get("content") or "").strip()
                else:
                    model_answer = (data.get("text") or "").strip()

            answer_lc = model_answer.lower()
            unwanted = False
            reason = "unknown"

            if answer_lc.startswith("yes"):
                unwanted = True
                if "(" in model_answer and ")" in model_answer:
                    reason = model_answer.split("(", 1)[1].split(")", 1)[0].strip()
                else:
                    for kw in ["gambling", "streaming", "porn", "adult", "malicious", "ai_tool", "social_media", "distracting"]:
                        if kw in answer_lc:
                            reason = kw
                            break
                    if reason == "unknown":
                        reason = "unwanted"
            else:
                unwanted = False
                reason = "allowed"

            if unwanted and in_no_block_list(domain):
                log_site(domain, "ALLOWED", "whitelisted")
                return {"unwanted": False, "reason": "whitelisted", "model_answer": model_answer}

            if unwanted:
                add_blocked_site(domain)
                log_site(domain, "BLOCKED", reason)
            else:
                log_site(domain, "ALLOWED", reason)

            return {"unwanted": unwanted, "reason": reason, "model_answer": model_answer}

    except Exception as e:
        print(f"[WARNING] AI analyze failed for {domain}: {e}")
        log_site(domain, "ALLOWED", "ai_error")
        return {"unwanted": False, "reason": "ai_error"}

# ---------------- Run ----------------
if __name__ == "__main__":
    print(f"[INFO] NO_BLOCK_DOMAINS = {NO_BLOCK_DOMAINS}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
