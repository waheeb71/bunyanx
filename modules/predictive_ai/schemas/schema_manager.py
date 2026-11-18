import json
import os

class SchemaManager:
    """
    Manages and validates schemas for the AEGIS data pipeline.
    """
    def __init__(self, schemas_dir):
        self.schemas_dir = schemas_dir
        if not os.path.exists(schemas_dir):
            os.makedirs(schemas_dir)
            
        # The base UEM schema
        self.uem_schema = {
            "event_id": str,
            "timestamp": str,
            "source_type": str,
            "dataset_source": str,
            "entity_id": (str, type(None)),
            "action": str,
            "attributes": dict,
            "label_raw": str,
            "is_attack": int,
            "attack_type": str,
            "processing_metadata": dict
        }
        
    def _save_schema(self, name, schema_dict):
        path = os.path.join(self.schemas_dir, f"{name}.json")
        with open(path, 'w', encoding='utf-8') as f:
            # Dump keys to keep it documented, actual type checking requires the dict in memory
            schema_doc = {k: str(v) for k, v in schema_dict.items()}
            json.dump(schema_doc, f, indent=4)
            
    def init_schemas(self):
        self._save_schema("uem_schema_v1", self.uem_schema)
        
    def validate_uem_event(self, event):
        """
        Validates an event against the UEM schema.
        Returns (is_valid, missing_keys, invalid_types).
        """
        missing_keys = []
        invalid_types = []
        
        for key, expected_type in self.uem_schema.items():
            if key not in event:
                missing_keys.append(key)
            else:
                # Handle union types (like str or None)
                if isinstance(expected_type, tuple):
                    if not isinstance(event[key], expected_type):
                        invalid_types.append((key, type(event[key]).__name__, " | ".join([t.__name__ for t in expected_type])))
                else:
                    if not isinstance(event[key], expected_type):
                        invalid_types.append((key, type(event[key]).__name__, expected_type.__name__))
                        
        return len(missing_keys) == 0 and len(invalid_types) == 0, missing_keys, invalid_types
