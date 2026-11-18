import json
import os
from datetime import datetime, timezone
import hashlib

class CheckpointManager:
    """
    Manages stage checkpoints to allow safe resumption of the pipeline.
    """
    def __init__(self, checkpoints_dir):
        self.checkpoints_dir = checkpoints_dir
        if not os.path.exists(checkpoints_dir):
            os.makedirs(checkpoints_dir)
            
    def _get_checkpoint_path(self, stage):
        return os.path.join(self.checkpoints_dir, f"checkpoint_stage_{stage}.json")
        
    def save_checkpoint(self, stage, completed_files, failed_files, offsets, pipeline_version, extra_data=None):
        checkpoint = {
            "stage": stage,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pipeline_version": pipeline_version,
            "completed_files": completed_files,
            "failed_files": failed_files,
            "offsets": offsets,
        }
        
        if extra_data:
            checkpoint.update(extra_data)
            
        path = self._get_checkpoint_path(stage)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(checkpoint, f, indent=4)
            
        return path
        
    def load_checkpoint(self, stage):
        path = self._get_checkpoint_path(stage)
        if not os.path.exists(path):
            return None
            
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def compute_file_hash(self, filepath):
        """Computes SHA-256 hash of a file for integrity checking."""
        if not os.path.exists(filepath):
            return None
            
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
