import numpy as np
import sys

# Fast bit count (popcount) emulation for numpy uint64 arrays
# In a pure C++ extension, we would use _mm256_popcnt_epi64.
# Numpy 2.0 has np.bitwise_count, we use a fallback if not available.
def _popcount(arr):
    if hasattr(np, 'bitwise_count'):
        return np.bitwise_count(arr).sum(axis=-1)
    else:
        # Fallback for numpy < 2.0 using byte unfolding
        return np.unpackbits(arr.view(np.uint8), axis=-1).sum(axis=-1).sum(axis=-1)

class SimilarityEngine:
    """
    Sub-microsecond similarity computation using bitwise parallel queries.
    Uses Maximum Cosine/Hamming distance over ensembles.
    """
    
    def __init__(self, dimensions: int = 10048):
        self.dimensions = dimensions
        
    def hamming_similarity(self, target_hv: np.ndarray, prototype_matrix: np.ndarray) -> float:
        """
        Computes the maximum similarity between the target vector and any prototype in the matrix.
        Similarity = 1.0 - (Hamming_Distance / Dimensions)
        
        Returns 0.0 if prototype matrix is empty.
        """
        if prototype_matrix.shape[0] == 0:
            return 0.0
            
        # Target shape: (157,)
        # Matrices shape: (K, 157)
        # 1. Bitwise XOR broadcasts target against all prototypes in SIMD
        xor_res = np.bitwise_xor(prototype_matrix, target_hv)
        
        # 2. Popcount yields Hamming distance per prototype
        hamming_distances = _popcount(xor_res)
        
        # 3. Min distance -> Max Similarity
        min_dist = np.min(hamming_distances)
        
        # Convert to similarity score [0 - 1.0]
        similarity = 1.0 - (min_dist / self.dimensions)
        return float(similarity)
        
    def compute_all_signals(self, target_hv: np.ndarray, dga_mat: np.ndarray, phish_mat: np.ndarray, benign_mat: np.ndarray):
        """Computes all signal embeddings simultaneously."""
        s_dga = self.hamming_similarity(target_hv, dga_mat)
        s_phish = self.hamming_similarity(target_hv, phish_mat)
        s_benign = self.hamming_similarity(target_hv, benign_mat)
        
        return s_dga, s_phish, s_benign
