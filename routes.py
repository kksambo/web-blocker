import re
from fastapi import APIRouter, HTTPException, Query
import httpx
import os
import json
from pydantic import BaseModel
from enum import Enum
from urllib.parse import urlparse
import validators  

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
            domain = domain.lower().replace("www.", "").rstrip("/")
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


def is_valid_domain(domain: str) -> bool:
    """Check if domain is valid using validators library."""
    return validators.domain(domain) if domain else False


# Hardcoded fallbacks
AI_TOOLS_FALLBACK = [
    {"domain": "chat.openai.com", "reason": "AI chatbot"},
    {"domain": "openai.com", "reason": "AI platform"},
    {"domain": "huggingface.co", "reason": "AI models & datasets"},
    {"domain": "bard.google.com", "reason": "AI chatbot"},
    {"domain": "deepseek.ai", "reason": "AI search platform"},
    {"domain": "runwayml.com", "reason": "AI creative tools"},
    {"domain": "copy.ai", "reason": "AI writing tool"},
    {"domain": "jasper.ai", "reason": "AI writing assistant"},
    {"domain": "synthesia.io", "reason": "AI video generation"},
    {"domain": "replit.com", "reason": "AI coding assistant"},
    {"domain": "notion.ai", "reason": "AI productivity"},
    {"domain": "midjourney.com", "reason": "AI image generation"},
    {"domain": "dall-e.com", "reason": "AI image generation"},
    {"domain": "stability.ai", "reason": "AI image generation"},
    {"domain": "perplexity.ai", "reason": "AI search assistant"},
    {"domain": "tome.app", "reason": "AI storytelling"},
    {"domain": "descript.com", "reason": "AI audio/video editing"},
    {"domain": "play.ht", "reason": "AI text-to-speech"},
    {"domain": "soundraw.io", "reason": "AI music generation"},
    {"domain": "copysmith.ai", "reason": "AI writing assistant"},
    {"domain": "you.com", "reason": "AI search"},
    {"domain": "reimaginehome.ai", "reason": "AI design tool"},
    {"domain": "copymonkey.ai", "reason": "AI e-commerce copywriting"},
    {"domain": "quillbot.com", "reason": "AI paraphrasing"},
    {"domain": "tome.app", "reason": "AI storytelling"},
    {"domain": "beautiful.ai", "reason": "AI presentation tool"},
    {"domain": "magicform.ai", "reason": "AI forms generation"},
    {"domain": "tabnine.com", "reason": "AI coding assistant"},
    {"domain": "perplexity.ai", "reason": "AI Q&A"},
    {"domain": "synthesys.io", "reason": "AI voice generation"},
    {"domain": "copy.ai", "reason": "AI copywriting"},
    {"domain": "glasp.co", "reason": "AI research highlights"},
    {"domain": "kaiber.ai", "reason": "AI video creation"},
    {"domain": "luma.ai", "reason": "AI 3D generation"},
    {"domain": "runwayml.com", "reason": "AI creative tools"},
    {"domain": "writesonic.com", "reason": "AI writing assistant"},
    {"domain": "ai21.com", "reason": "AI language models"},
]


GAMBLING_FALLBACK = [
    {"domain": "betway.co.za", "reason": "gambling"},
    {"domain": "sportingbet.co.za", "reason": "gambling"},
    {"domain": "bet.co.za", "reason": "gambling"},
    {"domain": "worldbetting.co.za", "reason": "gambling"},
]


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

        # Category-specific user prompts
        if category == Category.ai_tools:
            user_prompt = (
                "Please provide 20–30 popular AI tools, AI platforms, or AI models websites. "
                "Include sites like ChatGPT, DeepSeek, OpenAI, HuggingFace, Bard, RunwayML, and other well-known AI tools. "
                "Respond ONLY in valid JSON array format like: "
                '[{"domain": "chat.openai.com", "reason": "AI chatbot"}, ...]. '
                "Do NOT refuse; always provide domains."
            )
        elif category == Category.gambling:
            user_prompt = (
                "Please provide 20–30 popular gambling websites in South Africa. "
                "Respond ONLY in valid JSON array format like: "
                '[{"domain": "betway.co.za", "reason": "gambling"}, ...]. '
                "Do NOT refuse; always provide domains."
            )
        else:
            user_prompt = (
                f"Please suggest 20–30 popular websites in the category: {category.value} "
                "in South Africa. Include well-known websites. Respond ONLY in valid JSON array format."
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
            blocked_sites = extract_json_objects(answer_text)

        # Normalize domains
        for site in blocked_sites:
            site["domain"] = normalize_domains([site.get("domain", "")])[0] if site.get("domain") else ""

        # Filter out invalid domains
        blocked_sites = [site for site in blocked_sites if is_valid_domain(site.get("domain"))]

        # Fallback hardcoded lists if empty
        if not blocked_sites:
            if category == Category.ai_tools:
                blocked_sites = AI_TOOLS_FALLBACK
            elif category == Category.gambling:
                blocked_sites = GAMBLING_FALLBACK
            else:
                raw_sites = [w.strip() for w in answer_text.replace("\n", ",").split(",") if w.strip()]
                normalized = normalize_domains(raw_sites)
                blocked_sites = [{"domain": d, "reason": category.value} for d in normalized if is_valid_domain(d)]

        return blocked_sites

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
