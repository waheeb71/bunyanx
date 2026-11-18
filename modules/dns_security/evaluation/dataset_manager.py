import os
import csv
import logging
import random
import requests
from typing import List, Tuple

logger = logging.getLogger(__name__)

# Paths for storing datasets
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DGA_FEED_URL = "http://osint.bambenekconsulting.com/feeds/dga-feed.txt"
BENIGN_FEED_URL = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"

os.makedirs(DATA_DIR, exist_ok=True)
DGA_FILE = os.path.join(DATA_DIR, "dga_domains.txt")
BENIGN_FILE = os.path.join(DATA_DIR, "benign_domains.txt")

class DatasetManager:
    """Manages the download and loading of evaluation datasets"""
    
    @classmethod
    def download_if_not_exists(cls, url: str, path: str, is_csv: bool = False, domain_col: int = 0) -> bool:
        if os.path.exists(path):
            return True
        logger.info(f"Downloading dataset from {url}...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            domains = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if is_csv:
                    parts = line.split(',')
                    if len(parts) > domain_col:
                        domains.append(parts[domain_col])
                else:
                    domains.append(line)
            
            with open(path, 'w', encoding='utf-8') as f:
                for d in domains:
                    f.write(f"{d}\n")
            logger.info(f"Successfully downloaded and saved to {path} ({len(domains)} domains)")
            return True
        except Exception as e:
            logger.error(f"Failed to download dataset from {url}: {e}")
            return False

    @classmethod
    def generate_random_dga(cls, count: int) -> List[str]:
        # Conficker-style: random chars, length 8-15
        import string
        domains = []
        tlds = ['.com', '.net', '.org', '.info']
        for _ in range(count):
            length = random.randint(8, 15)
            name = ''.join(random.choices(string.ascii_lowercase, k=length))
            tld = random.choice(tlds)
            domains.append(name + tld)
        return domains

    @classmethod
    def generate_dictionary_dga(cls, count: int) -> List[str]:
        # Matsnu-style: combination of 2-3 english words to evade Lexical analysis
        words = ["server", "update", "cloud", "api", "auth", "login", "sync", 
                 "network", "node", "app", "system", "host", "secure", "edge", 
                 "data", "stream", "live", "portal", "admin", "gateway", "connect"]
        domains = []
        tlds = ['.com', '.net', '.org', '.cc']
        for _ in range(count):
            word_count = random.randint(2, 3)
            name = ''.join(random.choices(words, k=word_count)) # No hyphens, just concatenated
            tld = random.choice(tlds)
            domains.append(name + tld)
        return domains

    @classmethod
    def generate_synthetic_benign(cls, count: int = 5000) -> List[str]:
        # Human-like patterns, often with hyphens and recognizable brands or names
        words = ["google", "youtube", "facebook", "aws", "microsoft", "apple", 
                 "news", "shop", "blog", "app", "pay", "mail", "dev", "docs"]
        tlds = ['.com', '.net', '.org', '.co.uk', '.edu', '.gov', '.io', '.co']
        domains = []
        for _ in range(count):
            word_count = random.randint(1, 3)
            name = '-'.join(random.choices(words, k=word_count))
            if random.random() > 0.8:
                name += str(random.randint(1, 100))
            tld = random.choice(tlds)
            domains.append(name + tld)
        return domains

    @classmethod
    def prepare_datasets(cls, max_samples: int = 10000) -> Tuple[List[str], List[str]]:
        """
        Returns a tuple of (dga_domains, benign_domains).
        """
        logging.basicConfig(level=logging.INFO)
        dga_domains = []
        benign_domains = []

        logger.warning("Using synthetic DGA domains (Conficker profile + Dictionary DGA profile).")
        # Generate 50% Random DGA, 50% Dictionary DGA (Matsnu)
        dga_domains.extend(cls.generate_random_dga(max_samples // 2))
        dga_domains.extend(cls.generate_dictionary_dga(max_samples // 2))

        logger.warning("Using synthetic Benign domains.")
        benign_domains = cls.generate_synthetic_benign(max_samples)

        # Sample and Shuffle
        if len(dga_domains) > max_samples:
            dga_domains = random.sample(dga_domains, max_samples)
        if len(benign_domains) > max_samples:
            benign_domains = random.sample(benign_domains, max_samples)

        random.shuffle(dga_domains)
        random.shuffle(benign_domains)
        
        return dga_domains, benign_domains

if __name__ == "__main__":
    d, b = DatasetManager.prepare_datasets(5000)
    print(f"Loaded {len(d)} DGA and {len(b)} Benign domains.")
