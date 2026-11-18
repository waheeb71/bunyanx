import numpy as np

class HDCEncoder:
    """
    Hyperdimensional Encoder for Domain Names.
    Converts a domain string into a 10,000-dimensional hypervector using:
    - Character Class embeddings
    - Positional permutations
    - N-gram bindings
    - Length scalar embeddings
    """
    def __init__(self, seed: int = 42, dimensions: int = 10048, ngram_size: int = 3):
        self.dimensions = dimensions
        self.ngram_size = ngram_size
        
        # Ensure dimensions is a multiple of 64 for AVX/SIMD bit-packing
        assert self.dimensions % 64 == 0, "Dimensions must be a multiple of 64"
        self.uint64_dim = self.dimensions // 64
        
        self.rng = np.random.default_rng(seed)
        
        # Memory map of item memory (Basis Vectors)
        self.item_memory = {}
        
        # Character Class Vectors
        self.class_digit = self._generate_hv()
        self.class_alpha = self._generate_hv()
        self.class_special = self._generate_hv()
        
        self.length_hv = self._generate_hv()
        
    def _generate_hv(self) -> np.ndarray:
        """Generates a random D-dimensional binary vector packed in uint64."""
        # A dense random binary vector where P(1) = 0.5
        uints = self.rng.integers(0, 2**64 - 1, size=self.uint64_dim, dtype=np.uint64)
        return uints

    def get_basis(self, char: str) -> np.ndarray:
        if char not in self.item_memory:
            self.item_memory[char] = self._generate_hv()
        return self.item_memory[char]
        
    def get_class_vector(self, char: str) -> np.ndarray:
        if char.isdigit():
            return self.class_digit
        elif char.isalpha():
            return self.class_alpha
        return self.class_special

    def _permute(self, hv: np.ndarray, shift: int) -> np.ndarray:
        """
        Position-aware permutation layer $\rho$.
        Cyclic bit-shift emulation over the uint64 block representation.
        Since exact 1-bit cross-boundary shifts in numpy arrays of uint64 are slow,
        we use block-level shifting and inter-block roll for fast positional awareness.
        """
        shift = shift % self.dimensions
        block_shift = shift // 64
        bit_shift = shift % 64
        
        rolled = np.roll(hv, block_shift)
        if bit_shift == 0:
            return rolled
            
        # Left shift the bits and bring overflows from the adjacent block
        # Note: This is an efficient numpy approximation of a giant bit-string cyclic shift.
        left = (rolled << np.uint64(bit_shift))
        right = np.roll(rolled, 1) >> np.uint64(64 - bit_shift)
        return left | right

    def bind(self, hv1: np.ndarray, hv2: np.ndarray) -> np.ndarray:
        """Bipolar multiplication is equivalent to logical XOR in dense binary."""
        return np.bitwise_xor(hv1, hv2)

    def bundle(self, hvs: list) -> np.ndarray:
        """
        Majority vote bundling. Converts bit-packed back to integer counts,
        finds majority, and repacks. Critical for superposition.
        """
        if not hvs:
            return np.zeros(self.uint64_dim, dtype=np.uint64)
            
        # Fast extraction of bits for majority voting
        # To avoid slow loops, we unpack -> sum -> threshold -> repack
        unpacked = np.array([np.unpackbits(v.view(np.uint8)) for v in hvs])
        majority = (unpacked.sum(axis=0) > (len(hvs) / 2)).astype(np.uint8)
        
        # Tie-breaker logic (random or assume 0, here assume 0)
        return np.packbits(majority).view(np.uint64)

    def encode_domain(self, domain: str) -> np.ndarray:
        """Encodes an entire domain name into a single Holographic representation."""
        if not domain:
            return np.zeros(self.uint64_dim, dtype=np.uint64)
            
        domain = domain.lower()
        sequence_hvs = []
        
        # Encode length as a scalar perturbation
        # Permute the length basis vector proportional to domain length
        length_encoded = self._permute(self.length_hv, len(domain)*3)
        sequence_hvs.append(length_encoded)
        
        # Convert chars to Class-Bound Vectors
        encoded_chars = []
        for i, char in enumerate(domain):
            base_v = self.get_basis(char)
            class_v = self.get_class_vector(char)
            # Bind character with its abstract class
            bound = self.bind(base_v, class_v)
            encoded_chars.append(bound)
            
        # Generate N-gram windows with Position-Aware Permutation $\rho$
        n = self.ngram_size
        for i in range(len(encoded_chars) - n + 1):
            ngram_v = encoded_chars[i]  # First char
            ngram_v = self._permute(ngram_v, 0)
            
            for j in range(1, n):
                char_v = self._permute(encoded_chars[i + j], j)
                ngram_v = self.bind(ngram_v, char_v)
                
            sequence_hvs.append(ngram_v)
            
        return self.bundle(sequence_hvs)
