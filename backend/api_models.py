# backend/api_models.py
from pydantic import BaseModel
from typing import List, Optional

# 1. Define the nested structure for Member 2's DOM data
class PageFeatures(BaseModel):
    form_count: int
    password_fields: int
    hidden_iframes: int
    has_external_action: bool

# 2. Define the exact REQUEST structure coming from the browser
class ScanRequest(BaseModel):
    url: str
    page_features: PageFeatures

# 3. Define the exact RESPONSE structure going back to the browser
class ScanResponse(BaseModel):
    risk_level: str
    score: float
    action: str
    reasons: List[str]