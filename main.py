from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import sqlite3
import datetime
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
import routes 

# ================= FastAPI App =================
app = FastAPI(title="Proxy Management API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for testing)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

app.include_router(routes.router)

DB_FILE = "proxy_app.db"

# ================= Database Setup =================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    # Blocked sites table
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT UNIQUE
        )
    """)
    # Logs table
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

# ================= Models =================
class User(BaseModel):
    email: str
    password: str

class Site(BaseModel):
    domain: str

class LogEntry(BaseModel):
    domain: str
    status: str  # "ALLOWED" or "BLOCKED"
    timestamp: str = None

# ================= User Endpoints =================
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

# ================= Blocked Sites Endpoints =================
@app.post("/block-site")
def block_site(site: Site):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blocked_sites (site) VALUES (?)", (site.domain,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Site already blocked")
    conn.close()
    return {"message": f"Site '{site.domain}' blocked successfully"}

@app.get("/blocked-sites", response_model=List[str])
def get_blocked_sites():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT site FROM blocked_sites")
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

# ================= Logs Endpoints =================
@app.post("/logs")
async def receive_log(log: LogEntry):
    timestamp = log.timestamp or datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs (domain, status, timestamp) VALUES (?, ?, ?)", (log.domain, log.status, timestamp))
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

# ================= Root =================
@app.get("/")
def root():
    return {"message": "Proxy Management API is running"}

# ================= Blocked Sites Endpoints =================
@app.delete("/blocked-sites/{domain}")
def delete_blocked_site(domain: str):
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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

