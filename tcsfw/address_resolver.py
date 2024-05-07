"""Address resolver"""

import os
from typing import List
from tcsfw.address import DNSName
from tcsfw.command_basics import read_env_file
from tcsfw.entity import SafeNameMap
from tcsfw.main import ConfigurationException
from tcsfw.model import Addressable


class AddressResolver:
    """Address resolver"""
    def __init__(self):
        self.safe_names = SafeNameMap(prefix="SUT_")
        self.addresses_for: List[Addressable] = []

    def require(self):
        """Require the addresses for entities"""
        env = read_env_file()
        for nb in self.addresses_for:
            env_name = self.safe_names.get_env_name(nb.entity)
            value = os.environ.get(env_name) or env.get(env_name)
            if not value:
                raise ConfigurationException(f"Environment variable {env_name} not defined for {nb.entity.long_name()}")
            address = DNSName.name_or_ip(value)
            nb.entity.addresses.add(address)
