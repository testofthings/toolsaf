class Scope:
    """A claim scope"""


class Claim:
    """A claim about the system entity, node, connection, etc."""
    def __init__(self, description=""):
        self.description = description

    def text(self) -> str:
        """Get full claim text"""
        return self.description

    def get_base_claim(self) -> 'Claim':
        """Get the base claim, different from self when claim copied for multiple checks"""
        return self

    def __repr__(self):
        return f"{self.description}"
