import json
import logging
import os
from datetime import datetime, timezone

class PipelineLogger:
    """
    Structured JSONL logger for the AEGIS data pipeline.
    Maintains separate log files for different categories of issues.
    """
    def __init__(self, log_dir):
        self.log_dir = log_dir
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        self.categories = {
            "parsing_failures": "parsing_failures.jsonl",
            "schema_violations": "schema_violations.jsonl",
            "corrupted_records": "corrupted_records.jsonl",
            "unresolved_entities": "unresolved_entities.jsonl",
            "failed_mitre_mappings": "failed_mitre_mappings.jsonl",
            "temporal_alignment_failures": "temporal_alignment_failures.jsonl",
            "session_merge_conflicts": "session_merge_conflicts.jsonl"
        }
        
    def _write_log(self, category, log_entry):
        if category not in self.categories:
            raise ValueError(f"Unknown log category: {category}")
            
        filepath = os.path.join(self.log_dir, self.categories[category])
        
        # Add common metadata
        log_entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')
            
    def log_parsing_failure(self, dataset, file, record_id, reason, stage):
        self._write_log("parsing_failures", {
            "dataset": dataset,
            "source_file": file,
            "record_id": record_id,
            "reason": reason,
            "stage": stage
        })
        
    def log_schema_violation(self, dataset, file, record_id, reason, stage, violated_field):
        self._write_log("schema_violations", {
            "dataset": dataset,
            "source_file": file,
            "record_id": record_id,
            "reason": reason,
            "stage": stage,
            "violated_field": violated_field
        })
        
    def log_corrupted_record(self, dataset, file, record_id, reason, stage, corruption_type):
        self._write_log("corrupted_records", {
            "dataset": dataset,
            "source_file": file,
            "record_id": record_id,
            "reason": reason,
            "stage": stage,
            "corruption_type": corruption_type
        })
        
    def log_unresolved_entity(self, entity_id, entity_type, evidence_tried, dataset, file, stage):
        self._write_log("unresolved_entities", {
            "entity_id": entity_id,
            "type": entity_type,
            "evidence_tried": evidence_tried,
            "dataset": dataset,
            "source_file": file,
            "stage": stage
        })
        
    def log_failed_mitre_mapping(self, label, technique_tried, reason, dataset, file, stage):
        self._write_log("failed_mitre_mappings", {
            "label": label,
            "technique_tried": technique_tried,
            "reason": reason,
            "dataset": dataset,
            "source_file": file,
            "stage": stage
        })
        
    def log_temporal_alignment_failure(self, record_id, timestamp_raw, issue, dataset, file, stage):
        self._write_log("temporal_alignment_failures", {
            "record_id": record_id,
            "timestamp_raw": timestamp_raw,
            "issue": issue,
            "dataset": dataset,
            "source_file": file,
            "stage": stage
        })
        
    def log_session_merge_conflict(self, session_ids, conflict_type, stage):
        self._write_log("session_merge_conflicts", {
            "session_ids": session_ids,
            "conflict_type": conflict_type,
            "stage": stage
        })
