#!/usr/from/env python3
"""
Enterprise bunyanx - Command Line Interface
Modular CLI tool for bunyanx management using Click
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import click
from api.cli.commands.auth import auth
from api.cli.commands.status import status
from api.cli.commands.rules import rules
from api.cli.commands.block import block
from api.cli.commands.stats import stats, anomalies, profile
from api.cli.commands.interfaces import interfaces

@click.group()
@click.version_option(version='2.0.0')
def cli():
    """
    Enterprise bunyanx Command Line Interface
    
    Hardware-aware Next-Generation Firewall management.
    """
    pass

# Register Modules
cli.add_command(auth)
cli.add_command(status)
cli.add_command(rules)
cli.add_command(block)
cli.add_command(stats)
cli.add_command(anomalies)
cli.add_command(profile)
cli.add_command(interfaces)

if __name__ == '__main__':
    cli()