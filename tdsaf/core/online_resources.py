"""Online resources and related keywords"""

class OnlineResource:
    """Online resource with keywords"""
    def __init__(self, name: str, url: str, keywords: list[str]):
        self.name = name
        self.url = url
        self.keywords = keywords
