"""
modules/waf/models.py
=====================
WAF-specific SQLAlchemy models.

These models were moved from system/database/database.py as part of the
architectural decoupling (Phase 2) to keep module-specific schemas inside
their respective modules.

The DatabaseManager's `_register_module_models()` mechanism auto-discovers
and registers these models into the shared metadata/engine on startup.
"""
from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from system.database.database import Base


class WAFTrainingData(Base):
    """
    WAF Self-Learning — stores every WAF decision for weekly model retraining.

    Enabled / disabled by WAFSettings.self_learning.enabled in waf.yaml.
    Max records enforced at write time by WAFSelfLearningLogger.
    """
    __tablename__ = 'waf_training_data'

    id             = Column(Integer, primary_key=True, autoincrement=True)
    timestamp      = Column(DateTime, default=datetime.utcnow, index=True)

    # ── Request fingerprint ──────────────────────────────────────────────
    src_ip         = Column(String(64), nullable=True, index=True)
    request_path   = Column(Text,       nullable=True)
    request_method = Column(String(16), nullable=True)
    payload        = Column(Text,       nullable=True)   # decoded text after Preprocessor

    # ── Extracted features (JSON snapshot) ───────────────────────────────
    features       = Column(JSON, nullable=True)

    # ── AI decision ───────────────────────────────────────────────────────
    risk_score     = Column(Float,      nullable=True)
    decision       = Column(String(32), nullable=True)   # ALLOW/CHALLENGE/SOFT_BLOCK/BLOCK
    nlp_score      = Column(Float,      nullable=True)
    bot_score      = Column(Float,      nullable=True)
    anomaly_score  = Column(Float,      nullable=True)
    reputation     = Column(Float,      nullable=True)

    # ── Ground-truth label (set by admin feedback or automation) ─────────
    # 0=benign  1=attack  2=suspicious  None=unreviewed
    label          = Column(Integer,    nullable=True, index=True)
    label_source   = Column(String(32), nullable=True)  # auto_block|admin_confirmed|fp_corrected

    # ── Versioning for retraining accountability ──────────────────────────
    model_version  = Column(String(64), nullable=True)

    def to_dict(self) -> dict:
        return {
            'id':             self.id,
            'timestamp':      self.timestamp.isoformat() if self.timestamp else None,
            'src_ip':         self.src_ip,
            'request_path':   self.request_path,
            'request_method': self.request_method,
            'risk_score':     self.risk_score,
            'decision':       self.decision,
            'label':          self.label,
            'label_source':   self.label_source,
            'model_version':  self.model_version,
        }
