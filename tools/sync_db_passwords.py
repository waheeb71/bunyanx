import os
import asyncio
import sys
from pathlib import Path

# Add project root to path so we can import modules
sys.path.append(str(Path(__file__).parent.parent.absolute()))

# Load environment variables from .env if present
try:
    import dotenv
    dotenv.load_dotenv(Path(__file__).parent.parent / ".env")
except ImportError:
    pass

# Bi-directional env var bridging
def bridge_env_vars():
    mappings = {
        "NGFW_SECRET_KEY": "bunyanx_SECRET_KEY",
        "NGFW_ADMIN_PASSWORD": "bunyanx_ADMIN_PASSWORD",
        "NGFW_OPERATOR_PASSWORD": "bunyanx_OPERATOR_PASSWORD",
        "NGFW_ENV": "bunyanx_ENV",
        "NGFW_GEOIP_PATH": "bunyanx_GEOIP_PATH",
        "NGFW_DATA_DIR": "bunyanx_DATA_DIR",
        "NGFW_ALLOWED_ORIGINS": "bunyanx_ALLOWED_ORIGINS",
    }
    for k1, k2 in mappings.items():
        v1 = os.getenv(k1)
        v2 = os.getenv(k2)
        if v1 and not v2:
            os.environ[k2] = v1
        elif v2 and not v1:
            os.environ[k1] = v2

bridge_env_vars()

from api.core.auth import _hash_password
from system.database.database import DatabaseManager, User
from sqlalchemy.future import select

async def main():
    # ── DB path resolution: same priority as engine.py ──────────────────────
    # 1. bunyanx_DATABASE_URL env var
    # 2. bunyanx_DB_PATH env var
    # 3. base.yaml database.path
    # 4. Fallback: data/bunyanx.db
    project_root = Path(__file__).parent.parent

    db_url = os.getenv('bunyanx_DATABASE_URL', '').strip()
    if not db_url:
        db_path_str = os.getenv('bunyanx_DB_PATH', '').strip()
        if not db_path_str:
            # Try to read from base.yaml
            base_yaml = project_root / 'system' / 'config' / 'base.yaml'
            try:
                import yaml as _yaml
                with open(base_yaml, encoding='utf-8') as _f:
                    _conf = _yaml.safe_load(_f) or {}
                db_path_str = _conf.get('database', {}).get('path', '')
            except Exception:
                pass
        db_path = (
            Path(db_path_str)
            if db_path_str and Path(db_path_str).is_absolute()
            else project_root / (db_path_str or 'data/bunyanx.db')
        )
        db_url = f"sqlite+aiosqlite:///{db_path.resolve()}"

    print(f"[*] Database URL: {db_url.replace('+aiosqlite', '')}")

    if db_url.startswith('sqlite') and not Path(db_url.split('///')[1]).exists():
        print(f"[!] Database file does not exist yet. Please run 'python main.py' first.")
        return

    db = DatabaseManager(db_url)
    await db.initialize()
    
    admin_pw = os.getenv("bunyanx_ADMIN_PASSWORD", "AdminSecureVal2026_987654321!")
    operator_pw = os.getenv("bunyanx_OPERATOR_PASSWORD", "OperatorSecureVal2026_987654321!")
    
    print(f"[*] Found passwords in environment/.env:")
    print(f"    - admin: {admin_pw}")
    print(f"    - operator: {operator_pw}")
    print(f"[*] Hashing and updating in database...")
    
    async with db.session() as session:
        # Update admin
        res_admin = await session.execute(select(User).filter_by(username='admin'))
        admin = res_admin.scalars().first()
        if admin:
            admin.password_hash = _hash_password(admin_pw)
            print("    [✓] Updated password for 'admin'")
        else:
            print("    [X] User 'admin' not found in database.")
            
        # Update operator
        res_op = await session.execute(select(User).filter_by(username='operator'))
        op = res_op.scalars().first()
        if op:
            op.password_hash = _hash_password(operator_pw)
            print("    [✓] Updated password for 'operator'")
        else:
            print("    [X] User 'operator' not found in database.")
            
        await session.commit()
    print("[*] Completed successfully! You can now log in using these passwords.")

if __name__ == "__main__":
    asyncio.run(main())
