from pydantic import BaseModel, Field

class DLPConfigSchema(BaseModel):
    is_active: bool = Field(True, description="Enable/disable core DLP scanning")
    block_on_match: bool = Field(True, description="Drop traffic that matches content regex rules")
    deception_enabled: bool = Field(True, description="Inject dummy honeypot tokens on leak detection")
    befp_enabled: bool = Field(True, description="Enable behavioral entropy flow profiling")
    befp_block_threshold: float = Field(0.80, description="ERS score threshold above which blocking occurs")
    befp_alert_threshold: float = Field(0.35, description="ERS score threshold above which alert triggers")
    w_entropy: float = Field(0.22, description="Weight for Shannon entropy signal")
    w_velocity: float = Field(0.18, description="Weight for flow velocity signal")
    w_chunking: float = Field(0.10, description="Weight for packet size chunking signal")
    w_protocol: float = Field(0.15, description="Weight for protocol entropy deviation signal")
    w_accumulation: float = Field(0.10, description="Weight for 24h exfiltration accumulation signal")

    # Additional YAML config fields
    model_path: str = Field("${NGFW_DATA_DIR}/models/befp_isolation_forest.pkl", description="Path to BEFP model")
    training_log: str = Field("${NGFW_DATA_DIR}/logs/befp_training.jsonl", description="Path to training log")
    feedback_db: str = Field("${NGFW_DATA_DIR}/db/befp_feedback.json", description="Path to feedback DB")
    weights_config: str = Field("${NGFW_DATA_DIR}/config/dlp_weights.json", description="Path to weights config")
    max_payload_bytes: int = Field(65536, description="Maximum payload bytes to analyze")
    log_rotation_days: int = Field(30, description="Number of days to keep logs")

    class Config:
        from_attributes = True
