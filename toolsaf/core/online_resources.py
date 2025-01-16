"""Online resources and related keywords"""
from typing import List


class OnlineResource:
    """Online resource with keywords"""
    def __init__(self, name: str, url: str, keywords: List[str]) -> None:
        self.name = name
        self.url = url
        self.keywords = keywords
