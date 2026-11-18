"""
Application Signatures
High-Performance Database of application signatures for DPI.
"""

from typing import Dict, Optional

class EncryptedAppSignatures:
    """Signatures for encrypted traffic (SNI/Cert based) using ultra-fast suffix dictionaries"""
    
    # Internal reverse-mapping: domain -> (app_id, category)
    _DOMAIN_MAP: Dict[str, tuple] = {
        "facebook.com": ("facebook", "social_media"),
        "fbcdn.net": ("facebook", "social_media"),
        "whatsapp.com": ("whatsapp", "messaging"),
        "whatsapp.net": ("whatsapp", "messaging"),
        "youtube.com": ("youtube", "streaming"),
        "googlevideo.com": ("youtube", "streaming"),
        "netflix.com": ("netflix", "streaming"),
        "nflxvideo.net": ("netflix", "streaming"),
        "tiktok.com": ("tiktok", "social_media"),
        "tiktokv.com": ("tiktok", "social_media"),
        "byteoversea.com": ("tiktok", "social_media"),
        "zoom.us": ("zoom", "conferencing"),
        "zoom.com": ("zoom", "conferencing"),
    }
    
    @staticmethod
    def identify_by_sni(sni: str) -> Optional[str]:
        # Fast hierarchical suffix lookup (x.y.com -> y.com -> com)
        parts = sni.lower().split('.')
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            if suffix in EncryptedAppSignatures._DOMAIN_MAP:
                return EncryptedAppSignatures._DOMAIN_MAP[suffix][0]
        return None

    @classmethod
    def get_category(cls, app_id: str) -> Optional[str]:
        if not hasattr(cls, '_CATEGORY_MAP'):
            cls._CATEGORY_MAP = {val[0]: val[1] for val in cls._DOMAIN_MAP.values()}
        return cls._CATEGORY_MAP.get(app_id)
