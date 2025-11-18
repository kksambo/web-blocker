# main.py
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
import routes

app = FastAPI()

# ---------------- Config ----------------
DB_FILE = "proxy_app.db"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"

NO_BLOCK_ENV = os.getenv("NO_BLOCK_DOMAINS", "web-blocker.onrender.com,localhost,127.0.0.1")
NO_BLOCK_DOMAINS = {d.strip().lower() for d in NO_BLOCK_ENV.split(",") if d.strip()}

# ---------------- App ----------------
app = FastAPI(title="Proxy Management API with AI Blocking (school-safe strict mode)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB Setup ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT UNIQUE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            status TEXT,
            timestamp TEXT,
            reason TEXT
        )
    """)

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
    status: str
    timestamp: Optional[str] = None
    reason: Optional[str] = None

class DomainRequest(BaseModel):
    domain: str

# ---------------- Utilities ----------------

def normalize_domain(domain: str) -> str:
    if not domain:
        return domain
    try:
        parsed = urlparse(domain if domain.startswith("http") else f"http://{domain}")
        domain_norm = parsed.netloc or parsed.path
        return domain_norm.lower().replace("www.", "").rstrip("/")
    except:
        return domain.lower().strip()

def is_valid_domain(domain: str) -> bool:
    try:
        return bool(domain) and validators.domain(domain)
    except:
        return False

def in_no_block_list(domain: str) -> bool:
    d = domain.lower()
    for nb in NO_BLOCK_DOMAINS:
        if d == nb or d.endswith("." + nb):
            return True
    return False

def add_blocked_site(domain: str):
    domain = normalize_domain(domain)
    if in_no_block_list(domain):
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_sites (site) VALUES (?)", (domain,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

def log_site(domain: str, status: str, reason: Optional[str] = None):
    ts = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (domain, status, reason, timestamp) VALUES (?, ?, ?, ?)",
              (domain, status, reason or "", ts))
    conn.commit()
    conn.close()

# ----------------------------------------------------------------------------------
# ⭐⭐⭐ STRICT SCHOOL SMART FILTER INSERTED HERE ⭐⭐⭐
# ----------------------------------------------------------------------------------

def strict_smart_filter(domain: str):
    """
    Smart school filter:
    - Blocks: porn, gambling, AI tools, social media, streaming, malicious, cheating
    - Allows: education sites only
    """

    d = domain.lower()

    # School safe auto-allow
    SCHOOL_SAFE = [
        "edu", "gov", "school", "study", "learn", "library", "scholar",
        "khanacademy", "wikipedia", "moodle", "blackboard",
        "academ", "research", "science", "university"
    ]
    for k in SCHOOL_SAFE:
        if k in d:
            return False, "educational"

    # Hard-block lists
    HARD_BLOCK = [
        # Adult
        "porn", "xvideos", "xnxx", "redtube", "xhamster", "pornhub",
        "brazzers", "onlyfans",

        # Gambling
        "betway", "bet365", "hollywoodbets", "sportingbet",
        "1xbet", "betsafe", "lottostar",

        # AI tools
        "openai", "chatgpt", "claude", "bard", "deepseek",
        "perplexity", "huggingface",

        # Social Media
        "facebook", "instagram", "tiktok", "snapchat",
        "twitter", "youtube", "pinterest",

        # Streaming
        "netflix", "showmax", "primevideo", "hulu", "disney",
        "fmovies", "soap2day", "putlocker", "123movies",

        # Malicious
        "malware", "phish", "scam", "ransom", "trojan", "hack"
    ]

    for k in HARD_BLOCK:
        if k in d:
            return True, k

    # Unknown → let AI check
    return None, None

# ----------------------------------------------------------------------------------


# ---------------- API ROUTES ----------------
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
        raise HTTPException(status_code=404, detail=f"Site '{domain}' not found")
    c.execute("DELETE FROM blocked_sites WHERE site=?", (domain,))
    conn.commit()
    conn.close()
    return {"message": f"Site '{domain}' removed"}

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


# ---------------- AI Analysis (strict mode) ----------------
@app.post("/analyze-domain")
async def analyze_domain(req: DomainRequest):

    domain = normalize_domain(req.domain)
    if not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    # 1️⃣ LOCAL STRICT SCHOOL FILTER
    local_check = strict_smart_filter(domain)

    if local_check != (None, None):
        unwanted, reason = local_check

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

    # 2️⃣ AI fallback (same as before)
    if not GROQ_API_KEY:
        log_site(domain, "ALLOWED", "no_api_key")
        return {"unwanted": False, "reason": "no_api_key"}

    system_prompt = (
        "You classify domains for school internet safety. "
        "Answer strictly 'Yes (reason)' or 'No'."
    )
    user_prompt = (
        f"Is '{domain}' unsafe for school? Categories: porn, gambling, streaming, social_media, "
        "ai_tool, malicious, distracting. Answer 'Yes (category)' or 'No'."
    )

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 10,
        "temperature": 0.0,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()

            data = res.json()
            message = data["choices"][0]["message"]["content"].strip()
            ans = message.lower()

            if ans.startswith("yes"):
                unwanted = True
                reason = ans.split("(")[1].split(")")[0] if "(" in ans else "unwanted"

                if in_no_block_list(domain):
                    log_site(domain, "ALLOWED", "whitelisted")
                    return {"unwanted": False, "reason": "whitelisted"}

                add_blocked_site(domain)
                log_site(domain, "BLOCKED", reason)
                return {"unwanted": True, "reason": reason, "model_answer": message}

            else:
                unwanted = False
                log_site(domain, "ALLOWED", "allowed")
                return {"unwanted": False, "reason": "allowed", "model_answer": message}

    except Exception as e:
        log_site(domain, "ALLOWED", "ai_error")
        return {"unwanted": False, "reason": "ai_error"}

# ---------------- Run ----------------
if __name__ == "__main__":
    print("[INFO] School-safe strict mode enabled")
    print("[INFO] NO_BLOCK_DOMAINS =", NO_BLOCK_DOMAINS)
    uvicorn.run(app, host="0.0.0.0", port=8000)
