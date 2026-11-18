import os
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import deque
import asyncio
try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

logger = logging.getLogger(__name__)

class UnifiedMemoryLogHandler(logging.Handler):
    """Buffers recent log messages in memory for real-time UI terminal."""
    def __init__(self, max_records=2000):
        super().__init__()
        self.max_records = max_records
        self.log_ring = deque(maxlen=max_records)
        self.formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.subscriptions: List[tuple] = []  # Stores (queue, loop)

    def emit(self, record):
        try:
            msg = self.format(record)
            entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage(),
                "formatted": msg
            }
            self.log_ring.append(entry)
            
            # Real-time streaming to active subscribers
            for queue, loop in self.subscriptions:
                if not loop.is_closed():
                    try:
                        loop.call_soon_threadsafe(queue.put_nowait, entry)
                    except Exception:
                        pass
        except Exception:
            self.handleError(record)

    def get_recent_logs(self, limit=500):
        return list(self.log_ring)[-limit:]

    async def subscribe(self):
        """Yields new logs as they arrive."""
        queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        subscriber = (queue, loop)
        self.subscriptions.append(subscriber)
        try:
            while True:
                yield await queue.get()
        finally:
            if subscriber in self.subscriptions:
                self.subscriptions.remove(subscriber)

# Global memory handler tied to the central controller
global_memory_handler = UnifiedMemoryLogHandler(max_records=2000)
global_memory_handler.setLevel(logging.INFO)

def _yield_lines_backward(file_path: str, chunk_size: int = 65536):
    """Memory-efficient backward line generator reading the file in chunks from the end."""
    if not os.path.exists(file_path):
        return
    try:
        with open(file_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            position = file_size
            buffer = bytearray()
            
            while position > 0:
                to_read = min(chunk_size, position)
                position -= to_read
                f.seek(position)
                chunk = f.read(to_read)
                if not chunk:
                    break
                buffer[0:0] = chunk  # Prepend chunk
                
                while b'\n' in buffer:
                    index = buffer.rfind(b'\n')
                    line = buffer[index+1:]
                    buffer = buffer[:index]
                    decoded = line.decode('utf-8', errors='replace').rstrip('\r\n')
                    if decoded:
                        yield decoded
                    
            if len(buffer) > 0:
                decoded = buffer.decode('utf-8', errors='replace').rstrip('\r\n')
                if decoded:
                    yield decoded
    except Exception as e:
        logger.error(f"Failed to read file backward: {file_path}. Error: {e}")

def setup_terminal_logging():
    """Attaches the memory log handler to the root logger."""
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, UnifiedMemoryLogHandler):
            return
    root_logger.addHandler(global_memory_handler)

def is_safe_path(base_dir: str, target_file: str) -> bool:
    """Path traversal protection: verifies target_file is strictly within base_dir."""
    if not target_file:
        return False
    base_abs = os.path.realpath(os.path.abspath(base_dir))
    target_abs = os.path.realpath(os.path.abspath(os.path.join(base_abs, target_file)))
    return os.path.commonpath([base_abs, target_abs]) == base_abs

# Default events DB path: data/events.db relative to the project root
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_DEFAULT_EVENTS_DB = os.path.join(_PROJECT_ROOT, "data", "events.db")


class LogController:
    """Manages system `.log` files, filtering, flushing, searching, and security event ingestion."""

    def __init__(self, log_dir: str = "logs", event_db_path: str = _DEFAULT_EVENTS_DB):
        self.log_dir = os.path.abspath(log_dir)
        os.makedirs(self.log_dir, exist_ok=True)
        # Ensure data/ directory exists for events DB
        os.makedirs(os.path.dirname(os.path.abspath(event_db_path)), exist_ok=True)
        self.memory_handler = global_memory_handler
        self.event_db_path = os.path.abspath(event_db_path)
        
        # Ensure root logger has UnifiedMemoryLogHandler attached
        setup_terminal_logging()
    
    def _query_events_fallback_sync(self, events_dir: str, src_ip: Optional[str], verdict: Optional[str], category: Optional[str], limit: int) -> List[Dict[str, Any]]:
        """Synchronous helper for querying fallback JSON events, run in thread executor."""
        results = []
        try:
            all_evt_files = [f for f in os.listdir(events_dir) if f.endswith('.json') and is_safe_path(events_dir, f)]
            all_evt_files.sort(key=lambda x: os.path.getmtime(os.path.join(events_dir, x)), reverse=True)
            
            # Search inside top files (newest first)
            for file_name in all_evt_files[:5]:
                full_path = os.path.join(events_dir, file_name)
                for line in _yield_lines_backward(full_path):
                    try:
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue
                        evt = json.loads(line_stripped)
                        # Filter
                        if src_ip and src_ip not in str(evt):
                            continue
                        if verdict and evt.get('verdict') != verdict:
                            continue
                        if category:
                            cat_upper = category.upper()
                            evt_cat = str(evt.get('category') or evt.get('module') or '').upper()
                            if cat_upper not in evt_cat and evt_cat not in cat_upper:
                                continue
                        
                        results.append(evt)
                        if len(results) >= limit:
                            break
                    except Exception:
                        continue
                if len(results) >= limit:
                    break
        except Exception as e:
            logger.error(f"Failed to read fallback events from JSON: {e}")
        return results

    async def query_events(self, src_ip: Optional[str] = None, verdict: Optional[str] = None, category: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Queries the security events database (Visitor Tracking) with fallback to JSON logs."""
        results = []
        db_queried = False
        
        # 1. Try SQLite Query first if library is available and file exists
        if AIOSQLITE_AVAILABLE and os.path.exists(self.event_db_path) and os.path.getsize(self.event_db_path) > 0:
            try:
                async with aiosqlite.connect(self.event_db_path) as db:
                    db.row_factory = aiosqlite.Row

                    # ── Schema introspection (cached per connection) ──────────
                    # REM-LM-01 FIX: The `module` column may not exist in all
                    # deployed schemas. Query PRAGMA to get actual column list
                    # before building the WHERE clause — avoids the repeated
                    # "no such column: module" error that floods the log.
                    existing_cols: set = set()
                    try:
                        async with db.execute("PRAGMA table_info(events)") as pragma_cur:
                            async for pragma_row in pragma_cur:
                                existing_cols.add(pragma_row[1])  # index 1 = column name
                    except Exception:
                        pass  # PRAGMA failure is non-fatal; query will still run without filters

                    query = "SELECT * FROM events WHERE 1=1"
                    params = []

                    if src_ip:
                        query += " AND src_ip = ?"
                        params.append(src_ip)
                    if verdict:
                        query += " AND verdict = ?"
                        params.append(verdict)
                    if category:
                        # Use `module` only if the column actually exists in this schema;
                        # otherwise fall back to raw_data full-text search.
                        if "module" in existing_cols:
                            query += " AND (module LIKE ? OR raw_data LIKE ?)"
                            params.append(f"%{category}%")
                            params.append(f"%{category}%")
                        elif "raw_data" in existing_cols:
                            query += " AND raw_data LIKE ?"
                            params.append(f"%{category}%")
                        elif "category" in existing_cols:
                            query += " AND category LIKE ?"
                            params.append(f"%{category}%")
                        # If no suitable column is found, skip the category filter silently

                    query += " ORDER BY timestamp DESC LIMIT ?"
                    params.append(limit)
                    
                    async with db.execute(query, params) as cursor:
                        async for row in cursor:
                            results.append(dict(row))
                db_queried = True
            except Exception as e:
                logger.error(f"Error querying event database: {e}")

        # 2. Smart Fallback: Read from JSON logs if DB is empty or unavailable
        if not db_queried or len(results) == 0:
            logger.info("Database empty or unavailable. Falling back to JSON event logs.")
            # Scan the logs/events directory
            events_dir = os.path.join(self.log_dir, "events")
            if os.path.exists(events_dir):
                fallback_results = await asyncio.get_running_loop().run_in_executor(
                    None, self._query_events_fallback_sync, events_dir, src_ip, verdict, category, limit
                )
                results.extend(fallback_results)

        # Deduplicate results
        seen_ids = set()
        final_results = []
        for r in results:
            eid = r.get('event_id') or f"{r.get('timestamp')}-{r.get('src_ip')}"
            if eid not in seen_ids:
                final_results.append(r)
                seen_ids.add(eid)

        return final_results[:limit]

    async def ingest_event(self, event_data: Dict[str, Any]) -> None:
        """Ingests a structured security or system event into storage (SQLite events.db and JSON logs)."""
        if not isinstance(event_data, dict):
            return

        if "timestamp" not in event_data:
            event_data["timestamp"] = datetime.utcnow().isoformat() + "Z"
        if "event_id" not in event_data:
            import uuid
            event_data["event_id"] = f"EVT-{uuid.uuid4().hex[:8].upper()}"

        # 1. Store in SQLite DB
        if AIOSQLITE_AVAILABLE and os.path.exists(self.event_db_path):
            try:
                async with aiosqlite.connect(self.event_db_path) as db:
                    await db.execute(
                        """
                        CREATE TABLE IF NOT EXISTS events (
                            event_id TEXT PRIMARY KEY,
                            timestamp TEXT,
                            module TEXT,
                            level TEXT,
                            src_ip TEXT,
                            dst_ip TEXT,
                            verdict TEXT,
                            action TEXT,
                            message TEXT,
                            raw_data TEXT
                        )
                        """
                    )
                    await db.execute(
                        """
                        INSERT OR REPLACE INTO events (event_id, timestamp, module, level, src_ip, dst_ip, verdict, action, message, raw_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_data.get("event_id"),
                            event_data.get("timestamp"),
                            event_data.get("module", "system"),
                            event_data.get("level", "INFO"),
                            event_data.get("src_ip"),
                            event_data.get("dst_ip"),
                            event_data.get("verdict") or event_data.get("action", "ALLOW"),
                            event_data.get("action"),
                            event_data.get("message", ""),
                            json.dumps(event_data)
                        )
                    )
                    await db.commit()
            except Exception as e:
                logger.error(f"Failed to write event to SQLite DB: {e}")

        # 2. Write to JSON file sink
        events_dir = os.path.join(self.log_dir, "events")
        os.makedirs(events_dir, exist_ok=True)
        today_str = datetime.utcnow().strftime("%Y-%m-%d")
        daily_json_path = os.path.join(events_dir, f"events_{today_str}.json")
        try:
            with open(daily_json_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_data) + "\n")
        except Exception as e:
            logger.error(f"Failed to append event to JSON log: {e}")

    def list_log_files(self) -> List[str]:
        files = ["Live Memory Buffer"]
        logger.info(f"Listing log files in directory: {self.log_dir}")
        if not os.path.exists(self.log_dir):
            logger.warning(f"Log directory DOES NOT EXIST: {self.log_dir}")
            return files
        
        try:
            disk_files = [f for f in os.listdir(self.log_dir) if (f.endswith('.log') or f.endswith('.json')) and is_safe_path(self.log_dir, f)]
            disk_files.sort(key=lambda x: os.path.getmtime(os.path.join(self.log_dir, x)), reverse=True)
            events_dir = os.path.join(self.log_dir, "events")
            if os.path.exists(events_dir):
                evt_files = [f"events/{f}" for f in os.listdir(events_dir) if (f.endswith('.json') or f.endswith('.log')) and is_safe_path(events_dir, f)]
                evt_files.sort(key=lambda x: os.path.getmtime(os.path.join(self.log_dir, x)), reverse=True)
                disk_files.extend(evt_files)
            files.extend(disk_files)
        except Exception as e:
            logger.error(f"Failed to list files in {self.log_dir}: {e}")
            
        return files
        
    def search_logs(self, file_name: Optional[str] = None, level: Optional[str] = None, keyword: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        """A robust line-based parser for searching standard log files or JSON events."""
        results = []
        if file_name:
            if file_name != "Live Memory Buffer" and not is_safe_path(self.log_dir, file_name):
                raise ValueError(f"Access denied: Path traversal detected in file parameter '{file_name}'")
            target_files = [file_name]
        else:
            target_files = self.list_log_files()
        
        if "Live Memory Buffer" in target_files:
            memory_logs = self.memory_handler.get_recent_logs(limit=limit * 5)
            for entry in reversed(memory_logs):
                line_stripped = entry["formatted"]
                if keyword and keyword.lower() not in line_stripped.lower():
                    continue
                if level and level.upper() not in entry["level"].upper():
                    continue
                    
                results.append({
                    "file": "Live Memory Buffer",
                    "content": line_stripped
                })
                if len(results) >= limit:
                    break

        for f in target_files:
            if f == "Live Memory Buffer": continue
            if not is_safe_path(self.log_dir, f):
                logger.warning(f"Skipping unsafe file path during search: {f}")
                continue
            file_path = os.path.join(self.log_dir, f)
            if not os.path.isfile(file_path):
                continue
                
            try:
                file_found_count = 0
                for line in _yield_lines_backward(file_path):
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                        
                    # Apply filters
                    if keyword and keyword.lower() not in line_stripped.lower():
                        continue
                    if level and level.upper() not in line_stripped.upper():
                        continue
                    
                    # Try parsing as JSON for structured logs, otherwise return raw text
                    content = line_stripped
                    try:
                        if line_stripped.startswith('{') and line_stripped.endswith('}'):
                            content = json.loads(line_stripped)
                    except json.JSONDecodeError:
                        pass
                        
                    results.append({
                        "file": f,
                        "content": content
                    })
                    file_found_count += 1
                    
                    if len(results) >= limit:
                        logger.info(f"Search in {f} completed. Total findings: {len(results)}")
                        return results
                logger.debug(f"Search in {f} found {file_found_count} lines.")
            except Exception as e:
                logger.error(f"Error reading log file {f}: {e}")
                
        logger.info(f"Log search completed. Total results: {len(results)}")
        return results

    def clear_logs(self, file_name: Optional[str] = None) -> int:
        """Truncates specific log file or all log files."""
        if file_name:
            if file_name != "Live Memory Buffer" and not is_safe_path(self.log_dir, file_name):
                raise ValueError(f"Access denied: Path traversal detected in file parameter '{file_name}'")
            target_files = [file_name]
        else:
            target_files = [f for f in self.list_log_files() if f != "Live Memory Buffer"]

        cleared = 0
        for f in target_files:
            if f == "Live Memory Buffer":
                continue
            if not is_safe_path(self.log_dir, f):
                logger.warning(f"Skipping unsafe file path during clear: {f}")
                continue
            file_path = os.path.join(self.log_dir, f)
            try:
                if os.path.isfile(file_path):
                    with open(file_path, 'w', encoding='utf-8') as log_file:
                        log_file.truncate(0)
                    cleared += 1
            except Exception as e:
                logger.error(f"Error clearing log file {f}: {e}")
        return cleared

    def get_stats(self) -> Dict[str, Any]:
        total_size = 0
        files = self.list_log_files()
        for f in files:
            if f == "Live Memory Buffer" or not is_safe_path(self.log_dir, f):
                continue
            file_path = os.path.join(self.log_dir, f)
            if os.path.isfile(file_path):
                total_size += os.path.getsize(file_path)
        return {
            "total_files": len(files),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "log_dir": self.log_dir
        }

class LogControllerManager:
    """Singleton pattern to access the controller globally within the module."""
    _instance = None
    
    @classmethod
    def get_instance(cls, config: Dict[str, Any] = None) -> LogController:
        setup_terminal_logging()
        if cls._instance is None:
            settings = config if config else {}
            log_dir = settings.get("primary_log_dir", "logs")
            raw_path = settings.get("event_db_path", _DEFAULT_EVENTS_DB)
            event_db_path = raw_path if os.path.isabs(raw_path) else os.path.join(_PROJECT_ROOT, raw_path)
            cls._instance = LogController(log_dir=log_dir, event_db_path=event_db_path)
        elif config is not None:
            log_dir = config.get("primary_log_dir", "logs")
            raw_path = config.get("event_db_path", _DEFAULT_EVENTS_DB)
            event_db_path = raw_path if os.path.isabs(raw_path) else os.path.join(_PROJECT_ROOT, raw_path)
            cls._instance.log_dir = os.path.abspath(log_dir)
            cls._instance.event_db_path = os.path.abspath(event_db_path)
            os.makedirs(cls._instance.log_dir, exist_ok=True)
            os.makedirs(os.path.dirname(cls._instance.event_db_path), exist_ok=True)

            if "default_level" in config:
                lvl_name = str(config["default_level"]).upper()
                lvl = getattr(logging, lvl_name, logging.INFO)
                global_memory_handler.setLevel(lvl)
                logging.getLogger().setLevel(lvl)

            logger.info(f"LogController updated with config. Dir: {cls._instance.log_dir}")

        return cls._instance

