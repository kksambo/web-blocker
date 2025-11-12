import re
from fastapi import APIRouter, HTTPException, BackgroundTasks
import httpx
import os
import json
from pydantic import BaseModel
from urllib.parse import urlparse

router = APIRouter(prefix="/suggest", tags=["suggest"])

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL_NAME = "llama-3.1-8b-instant"


class BlockedSite(BaseModel):
    domain: str
    reason: str  # explanation why it might be blocked


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
    """
    Extract all JSON objects from a string, ignoring extra commentary.
    Returns a list of Python dicts.
    """
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
async def suggest_blocked_sites(background_tasks: BackgroundTasks):
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set in environment")

    try:
        system_prompt = (
            "You are StudyBuddy, an AI administrative assistant. "
            "Do NOT provide academic answers. "
            "Suggest a list of websites that South African universities typically block for students, "
            "such as social media, streaming, gambling, or adult content sites. "
            "Provide each domain with a short reason why it might be blocked. "
            "Return the response as a JSON array like: "
            '[{"domain": "facebook.com", "reason": "social media"}, ...]'
        )

        user_prompt = "Please suggest 8-12 blocked websites for students in South Africa."

        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

        payload = {
            "model": MODEL_NAME,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": 300,
        }

        async with httpx.AsyncClient() as client:
            res = await client.post(GROQ_URL, headers=headers, json=payload)
            res.raise_for_status()
            data = res.json()

        answer_text = data["choices"][0]["message"]["content"].strip()

        # Extract JSON objects only
        blocked_sites = extract_json_objects(answer_text)

        # Normalize domains
        for site in blocked_sites:
            site["domain"] = normalize_domains([site["domain"]])[0] if site["domain"] else site["domain"]

        # Fallback if no JSON objects found
        if not blocked_sites:
            raw_sites = [w.strip() for w in answer_text.replace("\n", ",").split(",") if w.strip()]
            normalized = normalize_domains(raw_sites)
            blocked_sites = [{"domain": d, "reason": "blocked"} for d in normalized]

        return blocked_sites

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
