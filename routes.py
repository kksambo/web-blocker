import re
from fastapi import APIRouter, HTTPException, Query
import httpx
import os
import json
from pydantic import BaseModel
from enum import Enum
from urllib.parse import urlparse

router = APIRouter(prefix="/suggest", tags=["suggest"])

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"


class BlockedSite(BaseModel):
    domain: str
    reason: str


class Category(str, Enum):
    social_media = "social media"
    streaming = "streaming"
    gambling = "gambling"
    ai_tools = "ai tools"
    gaming = "gaming"
    shopping = "shopping"


def normalize_domains(raw_list):
    """Clean and normalize URLs/domains."""
    domains = []
    seen = set()
    for item in raw_list:
        item = item.strip().strip("<>").replace(" ", "")
        if not item:
            continue
        try:
            parsed = urlparse(item if item.startswith("http") else f"http://{item}")
            domain = parsed.netloc or parsed.path
            domain = domain.lower().replace("www.", "")
            if domain and domain not in seen:
                domains.append(domain)
                seen.add(domain)
        except Exception:
            continue
    return domains


def extract_json_objects(text):
    """Extract all JSON objects from a string."""
    objs = []
    for match in re.finditer(r"\{.*?\}", text, re.DOTALL):
        try:
            obj = json.loads(match.group())
            if "domain" in obj and "reason" in obj:
                objs.append(obj)
        except json.JSONDecodeError:
            continue
    return objs


@router.get("/blocked-sites", response_model=list[BlockedSite])
async def suggest_blocked_sites(category: Category = Query(..., description="Choose a category")):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set in environment")

    try:
        system_prompt = (
            "You are StudyBuddy, an AI administrative assistant. "
            "Do NOT provide academic answers. "
            "Suggest a list of websites in the category provided by the user. "
            "Return each domain with a short reason in JSON array like: "
            '[{"domain": "facebook.com", "reason": "social media"}, ...]'
        )

        user_prompt = (
            f"Please suggest 20–30 popular websites in the category: {category.value} "
            "in South Africa. Include well-known websites, if category is adult include adult sites. "
            "Respond ONLY in valid JSON array format."
        )

        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": 700,
        }

        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()
            data = res.json()

        answer_text = data["choices"][0]["message"]["content"].strip()

        # Try parsing JSON array first
        try:
            blocked_sites = json.loads(answer_text)
            if not isinstance(blocked_sites, list):
                blocked_sites = []
        except json.JSONDecodeError:
            # fallback: extract individual JSON objects
            blocked_sites = extract_json_objects(answer_text)

        # Normalize domains
        for site in blocked_sites:
            site["domain"] = normalize_domains([site.get("domain", "")])[0] if site.get("domain") else ""

        # Fallback if still empty
        if not blocked_sites:
            raw_sites = [w.strip() for w in answer_text.replace("\n", ",").split(",") if w.strip()]
            normalized = normalize_domains(raw_sites)
            blocked_sites = [{"domain": d, "reason": category.value} for d in normalized]

        return blocked_sites

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
