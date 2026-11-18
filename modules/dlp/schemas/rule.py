from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class DLPRuleBase(BaseModel):
    name: str = Field(..., description="Unique name of the DLP rule")
    pattern: str = Field(..., description="Regex pattern for matching data leaks")
    severity: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: Optional[str] = Field(None, description="Optional explanation of the rule")
    enabled: bool = Field(True, description="Whether the rule is active")

class DLPRuleCreate(DLPRuleBase):
    pass

class DLPRuleResponse(DLPRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
