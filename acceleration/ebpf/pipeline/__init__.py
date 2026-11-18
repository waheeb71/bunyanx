"""
bunyanx NGFW — eBPF Pipeline Package
=========================================
معمارية XDP Modular Pipeline بنظام Tail Calls.

الهيكل:
  dispatcher.c      ← البرنامج الرئيسي (يُحمّل على الـ NIC)
  stage_blacklist.c ← Stage 0: IP Blacklist
  stage_conntrack.c ← Stage 1: Stateful TCP (Phase 3)
  stage_syn_proxy.c ← Stage 2: SYN Cookie (Phase 4)
  stage_l4_lb.c     ← Stage 3: L4 Load Balancer (Phase 5)
"""
