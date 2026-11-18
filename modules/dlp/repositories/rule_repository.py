from sqlalchemy.orm import Session
from typing import List, Optional
from modules.dlp.models import DLPRule
from modules.dlp.schemas.rule import DLPRuleCreate

class RuleRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self, skip: int = 0, limit: int = 100) -> List[DLPRule]:
        return self.db.query(DLPRule).offset(skip).limit(limit).all()

    def get_by_name(self, name: str) -> Optional[DLPRule]:
        return self.db.query(DLPRule).filter(DLPRule.name == name).first()

    def get_by_id(self, rule_id: int) -> Optional[DLPRule]:
        return self.db.query(DLPRule).filter(DLPRule.id == rule_id).first()

    def create(self, rule: DLPRuleCreate) -> DLPRule:
        db_rule = DLPRule(**rule.dict())
        self.db.add(db_rule)
        self.db.commit()
        self.db.refresh(db_rule)
        return db_rule

    def delete(self, db_rule: DLPRule) -> None:
        self.db.delete(db_rule)
        self.db.commit()
