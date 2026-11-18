#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transparent/ package — public API re-exports.

All external code that imports from this package gets MITMProxy directly.
Keeps the public surface identical to the old monolithic transparent_proxy.py.
"""
from modules.proxy.engine.proxy_modes.transparent._proxy_core import MITMProxy

__all__ = ['MITMProxy']
