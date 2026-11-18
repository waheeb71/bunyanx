#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise bunyanx - Main Entry Point
═══════════════════════════════════════════════════════════════════

Author: Enterprise Security Team
License: Proprietary
Version: 2.0.0
"""

import sys
import os
import logging
import asyncio
import argparse
from pathlib import Path

# Load environment variables from .env if present
try:
    import dotenv
    dotenv.load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

# Bi-directional env var bridging to support both NGFW_ and bunyanx_ prefixes
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

# ── SECURITY: Validate secrets BEFORE loading any component ──────────────────
# This must run before any database, API, or engine initialization.
from system.security.startup_validator import validate_startup_security
validate_startup_security()

# Setup initial console logging formatting before engine load
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

# Add terrifying theme
custom_theme = Theme({
    "info": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "critical": "bold white on red",
})
console = Console(theme=custom_theme)

class ColorizeModuleFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.colors = [
            "cyan", "magenta", "green", "yellow", "blue", 
            "bright_cyan", "bright_magenta", "bright_green", 
            "bright_yellow", "bright_blue", "dark_orange",
            "deep_pink1", "spring_green1", "turquoise2"
        ]
    
    def filter(self, record):
        # Hash the module name to consistently pick a color
        color = self.colors[hash(record.name) % len(self.colors)]
        if not getattr(record, "_colorized", False):
            # Convert dicts/JSON strings appropriately or just format the string
            if isinstance(record.msg, str):
                record.msg = f"[bold {color}][{record.name}][/] {record.msg}"
            record._colorized = True
        return True

rich_handler = RichHandler(rich_tracebacks=True, console=console, show_path=False, markup=True)
rich_handler.addFilter(ColorizeModuleFilter())

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%Y-%m-%d %H:%M:%S]",
    handlers=[rich_handler]
)
logger = logging.getLogger(__name__)

# Setup Web UI Logging Ring Buffer
from modules.log_manager.engine.log_controller import setup_terminal_logging
setup_terminal_logging()

# Import the core engine
from system.core.engine import bunyanxApplication
from modules.ssl_inspection.engine.ca_pool import CAPoolManager

def _print_banner(app):
    """Print startup banner"""
    if not app.config:
        logger.info("[bold red]  ☠️  Enterprise bunyanx starting with default configuration[/]")
        return
        
    proxy_config = app.config.get('proxy', {})
    tls_config = app.config.get('tls', {})
    ebpf_config = app.config.get('ebpf', {})
    api_config = app.config.get('api', {})
    
    from rich.panel import Panel
    from rich.align import Align
    
    banner_text = (
        "[bold red]╔═══════════════════════════════════════════════════════════════════╗[/]\n"
        "[bold red]║[/]         [bold dark_red]☠️  Enterprise bunyanx - Successfully Started[/]                [bold red]║[/]\n"
        "[bold red]╚═══════════════════════════════════════════════════════════════════╝[/]\n\n"
        f"  [bold cyan]📡 Forward Proxy:[/]  [green]{proxy_config.get('forward_listen_host', '0.0.0.0')}:{proxy_config.get('forward_listen_port', 8080)}[/]\n"
        f"  [bold cyan]🔒 Reverse Proxy:[/]  [green]{proxy_config.get('reverse_listen_host', '0.0.0.0')}:{proxy_config.get('reverse_listen_port', 443)}[/]\n"
        f"  [bold cyan]📜 Root CA:[/]        [green]{tls_config.get('ca_cert_path', 'certs/root-ca.crt')}[/]\n"
        f"  [bold cyan]⚡ eBPF XDP:[/]       [magenta]{ebpf_config.get('enabled', False)}[/]\n"
        f"  [bold cyan]🧠 ML Engine:[/]      [magenta]{app.config.get('ml', {}).get('enabled', True)}[/]\n"
        f"  [bold cyan]🌐 VPN Server:[/]     [magenta]{app.vpn_enabled} (WireGuard)[/]\n"
        f"  [bold cyan]🔌 REST API:[/]       [green]http://{api_config.get('host', '0.0.0.0')}:{api_config.get('port', 8000)}[/]\n\n"
        "  [bold yellow blink]⚠️  IMPORTANT: Review SystemTerminal for Active Dashboard Logs![/]\n"
        "  [bold black on red] Press Ctrl+C to stop [/]"
    )
    
    console.print(Panel(Align.center(banner_text), border_style="red", title="[bold red]SYSTEM ONLINE[/]"))

async def async_main():
    parser = argparse.ArgumentParser(description='Enterprise bunyanx - Next-Generation Firewall')
    parser.add_argument('-c', '--config', type=Path, default=Path('system/config/base.yaml'), help='Configuration API Path')
    parser.add_argument('--init-ca', action='store_true', help='Initialize CA certificates and exit')
    parser.add_argument('--export-ca', type=Path, metavar='DIR', help='Export CA certificates for client installation and exit')
    
    args = parser.parse_args()
    
    # Handle special operations
    if args.init_ca or args.export_ca:
        app = bunyanxApplication(args.config)
        app.load_config()
        
        ca_manager = CAPoolManager(app.config)
        
        if args.export_ca:
            ca_manager.export_ca_for_clients(args.export_ca)
            logger.info(f"✅ CA certificates exported to {args.export_ca}")
        
        return
    
    # Normal operation
    app = bunyanxApplication(args.config)
    
    # Supress known Python 3.11 asyncio bug related to SSL Protocol Abort and EOF
    loop = asyncio.get_running_loop()
    def custom_exception_handler(loop, context):
        msg = context.get("message", "")
        exc = context.get("exception", None)
        if "Error calling eof_received" in str(msg) or (exc and "SSLProtocol._abort" in str(exc)):
            return  # Suppress this known benign bug noise
        loop.default_exception_handler(context)
    loop.set_exception_handler(custom_exception_handler)
    
    try:
        app.load_config()
        await app.initialize_components()
        
        # Start API server
        from api.main import app as api_app
        import uvicorn
        
        # Pass bunyanx instance to API
        api_app.state.bunyanx = app
        
        api_config = app.config.get('api', {})
        host = api_config.get('host', '0.0.0.0')
        port = api_config.get('port', 8000)
        
        _print_banner(app)
        
        # Start Firewall Engine Default Loop Thread
        await app.start_firewall_components()
        app.running = True
        
        # Run API
        config = uvicorn.Config(api_app, host=host, port=port, log_level="info", log_config=None)

        server = uvicorn.Server(config)
        await server.serve()
        
        await app.run_forever()
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        await app.stop()


if __name__ == '__main__':
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
        sys.exit(0)
