"""
fl/__init__.py — Federated Learning stack for Zhang et al. (2025).
"""
from zhang2025.fl.model import LogisticModel
from zhang2025.fl.client import FLClient
from zhang2025.fl.server import FLServer
from zhang2025.fl.data import make_synthetic_dataset, FederatedDataset, ClientDataset

__all__ = [
    "LogisticModel",
    "FLClient",
    "FLServer",
    "make_synthetic_dataset",
    "FederatedDataset",
    "ClientDataset",
]
