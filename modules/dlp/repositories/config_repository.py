from sqlalchemy.orm import Session
from typing import Optional
from modules.dlp.models import DLPConfig
from modules.dlp.schemas.config import DLPConfigSchema

class ConfigRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_config(self) -> DLPConfig:
        config = self.db.query(DLPConfig).first()
        if not config:
            config = DLPConfig()
            self.db.add(config)
            self.db.commit()
            self.db.refresh(config)
        return config

    def update_config(self, new_config: DLPConfigSchema) -> DLPConfig:
        config = self.db.query(DLPConfig).first()
        if not config:
            config = DLPConfig()
            self.db.add(config)

        for key, value in new_config.dict().items():
            if hasattr(config, key):
                setattr(config, key, value)

        self.db.commit()
        self.db.refresh(config)
        return config
