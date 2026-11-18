import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# ── Dynamic DB URL Resolution ────────────────────────────────────────────────
from pathlib import Path
database_url = os.environ.get('bunyanx_DATABASE_URL', '').strip()
if not database_url:
    _db_path_str = os.environ.get('bunyanx_DB_PATH', '').strip()
    if _db_path_str:
        _db_path = Path(_db_path_str)
    else:
        _project_root = Path(__file__).resolve().parent.parent.parent.parent
        _base_yaml_path = _project_root / 'system' / 'config' / 'base.yaml'
        _conf_db_path = ""
        if _base_yaml_path.exists():
            try:
                import yaml
                with open(_base_yaml_path, 'r', encoding='utf-8') as f:
                    _base_yaml = yaml.safe_load(f) or {}
                _conf_db_path = _base_yaml.get('database', {}).get('path', '')
            except Exception:
                pass
        
        if _conf_db_path:
            _db_path = Path(_conf_db_path) if Path(_conf_db_path).is_absolute() else _project_root / _conf_db_path
        else:
            _db_path = _project_root / 'data' / 'bunyanx.db'

    _db_path.parent.mkdir(parents=True, exist_ok=True)
    database_url = f'sqlite+aiosqlite:///{_db_path.resolve()}'

if database_url.startswith("sqlite://"):
    database_url = database_url.replace("sqlite://", "sqlite+aiosqlite://")
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")

config.set_main_option("sqlalchemy.url", database_url)
# ─────────────────────────────────────────────────────────────────────────────

from system.database.database import Base
# Import all module models so Base.metadata is fully populated for Alembic autogenerate.
# See system/database/model_registry.py for the full list.
import system.database.model_registry  # noqa: F401, E402
target_metadata = Base.metadata


# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
