"""
Enterprise bunyanx - Hardware Appliance Networking Package
=============================================================

Contains all hardware-level networking components for running
bunyanx as a physical/virtual appliance on Debian 12:

  interface_manager.py   — NIC discovery by MAC, systemd-networkd config, Hybrid Rollback
  netfilter_manager.py   — Atomic nftables abstraction with Lockout Protection
  os_init/               — OOBE setup (first-boot MGMT assignment) and Safe Mode boot script
"""
