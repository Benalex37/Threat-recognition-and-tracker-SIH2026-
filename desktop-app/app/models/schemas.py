from pydantic import BaseModel
from typing import Optional, Dict, Any


class AnalysisRequest(BaseModel):
    messageId: str
    sender: str
    subject: str
    emailBody: str
    headers: Dict[str, Any]


class BadgeScoreRequest(BaseModel):
    messageId: str
    sender: str
    subject: str
    # The preview line Gmail renders next to the subject in the inbox list.
    # Optional so older builds of the extension keep working.
    snippet: str = ""


class CategoryUpdate(BaseModel):
    enabledCategories: Dict[str, bool]


class HealthResponse(BaseModel):
    status: str


class EvidenceItem(BaseModel):
    factor: str
    contribution: int
    explanation: str


class AnalysisResult(BaseModel):
    messageId: str
    score: float
    flagged: bool
    category: Optional[str] = None
    safeScore: Optional[float] = None
    evidence: Optional[list[EvidenceItem]] = None
    processedLocally: bool = True


class StatsResponse(BaseModel):
    analyzed: int
    flagged: int
    safe: int
