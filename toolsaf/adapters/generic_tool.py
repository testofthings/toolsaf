"""Generic tool adapter"""

from io import BufferedReader
from datetime import datetime
import json

from toolsaf.common.address import Addresses
from toolsaf.core.event_interface import EventInterface, PropertyAddressEvent
from toolsaf.core.model import IoTSystem
from toolsaf.adapters.tools import SystemWideTool
from toolsaf.common.traffic import EvidenceSource, Evidence
from toolsaf.common.property import PropertyKey
from toolsaf.common.verdict import Verdict


class GenericTool(SystemWideTool):
    """Generic tool adapter"""
    def __init__(self, system: IoTSystem) -> None:
        super().__init__("generic", system)
        self.tool.name = "Generic tool"
        self.data_file_suffix = ".json"

    def process_file(self, data: BufferedReader, file_name: str, interface: EventInterface,
                     source: EvidenceSource) -> bool:
        js_data = json.load(data)

        # assuming it is fine to override evidence source fields
        tool_name = js_data.get("tool")
        if tool_name:
            source.name = str(tool_name)
        description = js_data.get("description")
        if description:
            source.description = str(description)
        timestamp_s = js_data.get("timestamp")
        if timestamp_s:
            source.timestamp = datetime.fromisoformat(timestamp_s)

        address_s = js_data.get("address")
        base_address = Addresses.parse_endpoint(address_s) if address_s else None

        js_results = js_data.get("results", [])
        if not isinstance(js_results, list):
            raise ValueError("Results must be a list")
        event_c = 0
        for i, js_res in enumerate(js_results):
            # one or more JSON-encoded events, property key is given as
            # - "key" as it is property key
            # - "claim" identifier of platform claim, delivered through properties
            key_s = js_res.get("key") or js_res.get("claim")
            if not key_s:
                raise ValueError('Missing "key" in event JSON data')
            key = PropertyKey.parse(key_s)

            address_s = js_res.get("address")
            if not address_s and not base_address:
                raise ValueError('Missing "address" in event JSON data')
            address = Addresses.parse_endpoint(address_s) if address_s else base_address
            assert address

            evidence = Evidence(source)
            evidence.tail_ref = js_res.get("ref") or f"#{i}"

            verdict = Verdict.parse(js_res.get("verdict", ""))
            exp = js_res.get("explanation", "")

            key_value = key.verdict(verdict, exp)
            event = PropertyAddressEvent(evidence, address, key_value)
            interface.property_address_update(event)
            event_c += 1

        return event_c > 0
