"""
test_server.py — Member 2's standalone test backend.

This is NOT the real project backend (that's Member 5's FastAPI app, which
will eventually import webpage_engine.score_webpage into its own /scan
endpoint alongside Members 1, 3, and 4's modules).

This file exists purely so Member 2 can test the JS -> JSON -> Python
pipeline end-to-end, right now, without waiting on anyone else.

Run with:
    uvicorn test_server:app --reload --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from webpage_engine import score_webpage, PageFeatures

app = FastAPI(title="Phishing Guard - Member 2 Test Server")

# Chrome extensions call this from a service worker context; CORS must be
# open here for local testing (the real backend will handle this properly).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class PageFeaturesModel(BaseModel):
    form_count: int
    password_fields: int
    hidden_iframes: int
    has_external_action: bool


class ScanRequest(BaseModel):
    url: str
    page_features: PageFeaturesModel


@app.post("/scan")
def scan(request: ScanRequest):
    features: PageFeatures = request.page_features.dict()
    result = score_webpage(features)
    print(f"[test_server] {request.url} -> {result}")
    return result


@app.get("/")
def health():
    return {"status": "Member 2 test server running"}
