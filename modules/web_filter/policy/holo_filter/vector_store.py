import numpy as np

class VectorStore:
    """
    Manages the Prototype Ensembles for DGA, Phishing, and Benign families.
    Responsible for fast in-memory AVX-ready lookups.
    """
    def __init__(self, dimensions: int = 10048):
        self.dimensions = dimensions
        self.uint64_dim = dimensions // 64
        
        # Stored as matrices: Shape (num_prototypes, uint64_dim)
        self.prototypes = {
            "dga": np.empty((0, self.uint64_dim), dtype=np.uint64),
            "phish": np.empty((0, self.uint64_dim), dtype=np.uint64),
            "benign": np.empty((0, self.uint64_dim), dtype=np.uint64)
        }
        
    def add_prototype(self, category: str, hv: np.ndarray):
        """Adds a new prototype hypervector to the specified subset."""
        if category not in self.prototypes:
            raise ValueError(f"Unknown category {category}")
            
        # Stack vertically for fast SIMD broadcasting later
        self.prototypes[category] = np.vstack([self.prototypes[category], hv])
        
    def save(self, filepath: str):
        """Exports weights for offline storage."""
        np.savez_compressed(filepath,
                            dga=self.prototypes["dga"],
                            phish=self.prototypes["phish"],
                            benign=self.prototypes["benign"])
                            
    def load(self, filepath: str):
        """Loads weights from disk."""
        try:
            data = np.load(filepath)
            self.prototypes["dga"] = data["dga"]
            self.prototypes["phish"] = data["phish"]
            self.prototypes["benign"] = data["benign"]
        except Exception as e:
            raise RuntimeError(f"Failed to load VectorStore: {e}")
            
    def get_matrices(self):
        """Returns the raw matrices for the similarity engine."""
        return self.prototypes['dga'], self.prototypes['phish'], self.prototypes['benign']
