# system/ml_core/__init__.py
# Generic ML framework utilities — do NOT import from modules/ here.
# Use the compatibility shim at system/ml_core/anomaly_detector.py if needed (backward-compat only).


class TrafficProfile:
    def __init__(self):
        self.reputation_score = 90.0

class TrafficProfiler:
    def __init__(self, time_window=300):
        self.time_window = time_window
        self.profiles = {}

    def profile_connection(self, src_ip, dst_ip, dst_port, protocol, bytes_sent, packets_sent):
        self.profiles[src_ip] = TrafficProfile()
        return "NORMAL", 0.95

    def get_ip_profile(self, ip):
        return self.profiles.get(ip)

    def get_statistics(self):
        return {"total_profiles": len(self.profiles)}

class AdaptivePolicyEngine:
    def __init__(self, learning_rate=0.1):
        self.learning_rate = learning_rate

    def evaluate(self, src_ip, dst_ip, dst_port, protocol, anomaly_score, reputation_score, pattern):
        action = "ALLOW" if anomaly_score < 0.5 else "BLOCK"
        return action, 0.9, "Policy evaluation"

    def add_feedback(self, src_ip, action_taken, was_threat, threat_type):
        pass

    def get_metrics(self):
        return {"evaluated_policies": 0}
