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
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  # set this in your environment if you want AI classification
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"

# ---------------- App ----------------
app = FastAPI(title="Proxy Management API with AI Blocking")

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
    # Users (kept as before)
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

def add_blocked_site(domain: str):
    """Insert domain into blocked_sites table (idempotent)."""
    domain = normalize_domain(domain)
    if not domain:
        return
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_sites (site) VALUES (?)", (domain,))
        conn.commit()
        print(f"[INFO] Added to blocked_sites: {domain}")
    except sqlite3.IntegrityError:
        # already exists
        pass
    finally:
        conn.close()

def log_site(domain: str, status: str):
    """Add a log entry for domain status."""
    ts = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (domain, status, timestamp) VALUES (?, ?, ?)", (domain, status, ts))
    conn.commit()
    conn.close()

# ---------------- Local fallback lists ----------------
AI_TOOLS = {
    "chat.openai.com", "openai.com", "huggingface.co", "bard.google.com", "runwayml.com",
    "perplexity.ai", "midjourney.com", "stability.ai", "replit.com"
}
GAMBLING_SITES = {"betway.co.za", "sportingbet.co.za", "bet.co.za", "worldbetting.co.za"}

# ---------------- Existing endpoints (users, blocked sites, logs) ----------------

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
    c.execute("INSERT INTO logs (domain, status, timestamp) VALUES (?, ?, ?)", (log.domain, log.status, ts))
    conn.commit()
    conn.close()
    return {"message": "Log received"}

@app.get("/logs", response_model=List[LogEntry])
def get_logs():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain, status, timestamp FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [{"domain": r[0], "status": r[1], "timestamp": r[2]} for r in rows]

@app.get("/")
def root():
    return {"message": "Proxy Management API is running"}

# ---------------- AI Analysis endpoint ----------------
@app.post("/analyze-domain")
async def analyze_domain(req: DomainRequest):
    """
    Receives JSON { "domain": "example.com" }
    Returns {"unwanted": true/false}
    If unwanted == true -> automatically adds to blocked_sites and logs it.
    """
    domain_raw = req.domain
    domain = normalize_domain(domain_raw)

    if not domain or not is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Quick local checks first
    if domain in AI_TOOLS or domain in GAMBLING_SITES:
        add_blocked_site(domain)
        log_site(domain, "BLOCKED")
        return {"unwanted": True}

    # If no API key, default to ALLOW but log it
    if not GROQ_API_KEY:
        log_site(domain, "ALLOWED")
        return {"unwanted": False}

    # Prepare prompts for the model (keep short deterministic answer)
    system_prompt = "You are a classifier that answers ONLY 'Yes' or 'No'."
    user_prompt = (
        f"Is the website domain '{domain}' unwanted for typical users (gambling, malicious, adult content, or an AI tool) ? "
        "Answer Yes or No."
    )

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "max_tokens": 8,
        "temperature": 0.0
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()
            data = res.json()

            # Attempt to parse common response formats
            answer_text = ""
            if isinstance(data, dict):
                # common structure: choices -> [ { message: { content: "Yes" } } ]
                choices = data.get("choices") or []
                if choices and isinstance(choices, list):
                    first = choices[0]
                    msg = first.get("message") or {}
                    answer_text = (msg.get("content") or "").strip().lower()
                else:
                    # fallback: try data['text'] or other fields
                    answer_text = (data.get("text") or "").strip().lower()

            answer_text = (answer_text or "").lower()
            unwanted = "yes" in answer_text

            if unwanted:
                add_blocked_site(domain)
                log_site(domain, "BLOCKED")
            else:
                log_site(domain, "ALLOWED")

            return {"unwanted": unwanted}

    except Exception as e:
        # On AI failure: log and default to allow (fail-open). You can change to fail-closed if desired.
        print(f"[WARNING] AI analyze failed for {domain}: {e}")
        log_site(domain, "ALLOWED")
        return {"unwanted": False}

# ---------------- Run ----------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
