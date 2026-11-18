import time
import statistics
from typing import Dict, Any

class EvaluatorMetrics:
    def __init__(self):
        self.tp = 0
        self.tn = 0
        self.fp = 0
        self.fn = 0
        self.latencies = []

    def record(self, is_malicious: bool, predicted_malicious: bool, latency_ms: float):
        if is_malicious and predicted_malicious:
            self.tp += 1
        elif not is_malicious and not predicted_malicious:
            self.tn += 1
        elif not is_malicious and predicted_malicious:
            self.fp += 1
        elif is_malicious and not predicted_malicious:
            self.fn += 1
        
        self.latencies.append(latency_ms)

    def compute(self) -> Dict[str, Any]:
        total = self.tp + self.tn + self.fp + self.fn
        accuracy = (self.tp + self.tn) / total if total > 0 else 0
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0
        
        avg_lat = statistics.mean(self.latencies) if self.latencies else 0
        p95_lat = statistics.quantiles(self.latencies, n=100)[94] if len(self.latencies) > 1 else avg_lat
        
        return {
            "Total Samples": total,
            "Accuracy": round(accuracy, 4),
            "Precision": round(precision, 4),
            "Recall (TPR)": round(recall, 4),
            "F1 Score": round(f1, 4),
            "False Positive Rate (FPR)": round(fpr, 4),
            "Avg Latency (ms)": round(avg_lat, 4),
            "P95 Latency (ms)": round(p95_lat, 4)
        }

    def print_report(self, title: str = "Evaluation Report"):
        print(f"\n{'='*40}")
        print(f"{title}")
        print(f"{'='*40}")
        res = self.compute()
        for k, v in res.items():
            print(f"{k:<30}: {v}")
        print(f"{'='*40}")
