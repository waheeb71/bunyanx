"""
PHANTOM — Model Package
=======================
Layer 3 of the PHANTOM framework.

Exports:
    PHANTOMClassifier   — PyTorch nn.Module (GNN + Transformer)
    PHANTOMInference    — Production inference wrapper (ONNX / PT / heuristic)
    PHANTOMResult       — Structured prediction output
    THREAT_CLASSES      — int → label mapping
    export_to_onnx      — Export trained model to ONNX for production
"""

from .phantom_classifier import (
    PHANTOMClassifier,
    PHANTOMInference,
    PHANTOMResult,
    THREAT_CLASSES,
    NUM_CLASSES,
    export_to_onnx,
)

__all__ = [
    "PHANTOMClassifier",
    "PHANTOMInference",
    "PHANTOMResult",
    "THREAT_CLASSES",
    "NUM_CLASSES",
    "export_to_onnx",
]
