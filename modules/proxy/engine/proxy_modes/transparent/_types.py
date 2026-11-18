#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Connection statistics dataclass — shared across all proxy submodules.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class ConnectionStats:
    """Connection statistics"""
    client_ip: str
    client_port: int
    target_host: str
    target_port: int
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: datetime = None
    end_time: Optional[datetime] = None

    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()
