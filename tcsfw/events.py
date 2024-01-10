import datetime
from typing import Optional

from tcsfw.property import PropertyKey


class ReleaseInfo:
    def __init__(self, sw_name: str):
        self.sw_name = sw_name
        self.latest_release: Optional[datetime.datetime] = None
        self.latest_release_name = "?"
        self.first_release: Optional[datetime.datetime] = None
        self.interval_days: Optional[int] = None

    @classmethod
    def parse_time(cls, date: Optional[str]) -> Optional[datetime.datetime]:
        return datetime.datetime.strptime(date, '%Y-%m-%d') if date else None

    @classmethod
    def print_time(cls, date: Optional[datetime.datetime]) -> str:
        return date.strftime('%Y-%m-%d') if date else ""

    def __repr__(self):
        r = f"Latest release {self.latest_release_name}"
        if self.latest_release:
            r += f" {self.print_time(self.latest_release)}"
        if self.interval_days is not None:
            r += f", avg. update interval {self.interval_days} days"
        return r

    # Key for release info as property
    PROPERTY_KEY = PropertyKey("default", "release-info")
