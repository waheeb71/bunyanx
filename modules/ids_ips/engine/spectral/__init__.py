"""
PHANTOM — Spectral Byte Encoder (SBE) Package
==============================================
Layer 1 of the PHANTOM framework.

Exports:
    spectral_byte_encode  — stateless single-call API
    SpectralCache         — LRU-cached wrapper for high-throughput use
"""

from .sbe import spectral_byte_encode, SpectralCache

__all__ = ["spectral_byte_encode", "SpectralCache"]
