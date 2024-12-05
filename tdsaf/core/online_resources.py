"""Online resources and related keywords"""

class OnlineResource:
    """Online resource base class"""
    keywords = {}
    name = "online-resource"


class PrivacyPolicy(OnlineResource):
    """Privacy policy"""
    keywords = {
        "privacy policy", "personal data", "information",
        "consent", "terms", "third party", "rights",
    }
    name = "privacy-policy"


class SecurityPolicy(OnlineResource):
    """Security policy"""
    keywords = {
        "vulnerability", "disclosure", "policy", "report", "bug", "threat",
        "incident", "scope", "submit", "security",
    }
    name = "security-policy"


class CookiePolicy(OnlineResource):
    """Cookie policy"""
    keywords = {
        "cookie policy", "stored", "delete", "block", "expire", "expiry",
        "consent", "personal data", "necessary", "functional", "marketing",
        "statistical"
    }
    name = "cookie-policy"
