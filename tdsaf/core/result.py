"""Simple text report on the system status"""
#pylint: disable=too-many-boolean-expressions

import sys
import shutil
import logging
from functools import cached_property
from typing import TextIO, List, Dict, Tuple, Union, Any
from colored import Fore, Style

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.common.verdict import Verdict
from tdsaf.core.model import Host, Connection, Addressable, NodeComponent, IoTSystem
from tdsaf.common.property import Properties, PropertyKey, PropertyVerdictValue
from tdsaf.core.registry import Registry


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.show: List[str] = []
        self.no_truncate = False
        self.use_color_flag = False
        self.logger = logging.getLogger("reporter")
        self.width = self.get_terminal_width()

    @cached_property
    def use_color(self) -> bool:
        """Determines if color text should be colored"""
        return self.use_color_flag or sys.stdout.isatty()

    @cached_property
    def green(self) -> str:
        """Green color"""
        return Fore.green if self.use_color else ""

    @cached_property
    def yellow(self) -> str:
        """Yellow color"""
        return Fore.rgb(255,220,101) if self.use_color else ""

    @cached_property
    def red(self) -> str:
        """Red color"""
        return Fore.red if self.use_color else ""

    @cached_property
    def bold(self) -> str:
        """Bold text"""
        return Style.bold if self.use_color else ""

    @cached_property
    def reset(self) -> str:
        """Reset colors/styles"""
        return Style.reset if self.use_color else ""

    @cached_property
    def show_all(self) -> bool:
        """Should all info be printed without text truncation"""
        return "all" in self.show

    def get_terminal_width(self) -> int:
        """Returns terminal width or fallback value"""
        width, _ = shutil.get_terminal_size(fallback=(90, 30))
        return width

    def get_system_verdict(self, cache: Dict [Entity, Verdict]) -> Verdict:
        """Get verdict for the entire system based on cached verdicts."""
        verdicts = cache.values()
        if Verdict.FAIL in verdicts:
            return Verdict.FAIL
        if Verdict.PASS in verdicts:
            return Verdict.PASS
        return Verdict.INCON

    def get_verdict_color(self, verdict: Union[Verdict, str]) -> str:
        """Returns color value for Verdict or string"""
        if isinstance(verdict, Verdict):
            if verdict == Verdict.INCON:
                return ""
            return [self.red, self.green, self.yellow][[Verdict.FAIL, Verdict.PASS, Verdict.IGNORE].index(verdict)]
        if isinstance(verdict, str):
            verdict = verdict.lower()
            if "/" in verdict:
                verdict_value = verdict.split("/")[1]
                return [self.red, self.green, ""][["fail", "pass", "incon"].index(verdict_value)]
            if "pass" in verdict:
                return self.green
            if "fail" in verdict:
                return self.red
            if "ignore" in verdict:
                return self.yellow
        return ""

    def print_title(self, text: str, writer: TextIO,
                    top_symbol: str="", bottom_symbol: str="") -> None:
        """Writes title sections to the output"""
        if top_symbol:
            writer.write(top_symbol * self.width + "\n")
        writer.write(text + "\n")
        if bottom_symbol:
            writer.write(bottom_symbol * self.width + "\n")

    def _get_sources(self, entity: Entity, key: PropertyKey=Properties.EXPECTED) -> List[str]:
        """Returns max self.source_count source strs for entity; if any"""
        if not self.source_count:
            return []
        sources = set(filter(None, [
            event.event.evidence.get_reference()
            for event in self.registry.logging.get_log(entity, key)
        ]))

        return list(sources)[:self.source_count]

    def get_properties_to_print(self, entity: Union[IoTSystem, Host, Addressable, NodeComponent, Connection]) \
                                -> List[Tuple[PropertyKey, Any]]:
        """Retuns properties that should be printed and the number of properties"""
        property_items = [(key, value) for key, value in entity.properties.items() if key!=Properties.EXPECTED]
        if self.show_all:
            return property_items

        result = []
        for key, value in property_items:
            if (is_instance:=isinstance(value, PropertyVerdictValue)) and (
                value.verdict == Verdict.FAIL or
                value.verdict == Verdict.IGNORE and "ignored" in self.show or
                value.verdict != Verdict.IGNORE and "properties" in self.show
            ) or not is_instance and "properties" in self.show:
                result += [(key, value)]
        return result

    def _get_addresses(self, host: Host) -> str:
        """Get addresses for given host"""
        addresses = [f"{address}" for address in sorted(host.addresses)]
        addresses = [address for address in addresses if address != host.name]
        return ", ".join(addresses)

    def _get_text(self, key: PropertyKey, value: Any) -> str:
        """Get text to print"""
        value_string = key.get_value_string(value)
        comment = key.get_explanation(value)
        comment = f" # {comment}" if comment else ""
        if isinstance(value, PropertyVerdictValue) or "=verdict" in value_string.lower():
            value_string = value_string.split("=")[0]
        return f"{value_string}{comment}"

    def _get_properties(self, entity: Union[IoTSystem, Host, Addressable, NodeComponent, Connection]) \
                        -> Dict[str, Dict[str, Any]]:
        """Get a dictionary of properties for given entity"""
        properties = {}
        key: PropertyKey
        for key, value in self.get_properties_to_print(entity):
            text = self._get_text(key, value)
            verdict = key.get_verdict(entity.properties)

            properties[key.get_name()] = {
                "srcs": self._get_sources(entity, key),
                "verdict": verdict.value if verdict is not None else "",
                "text": text
            }
        return properties

    def _crop_text(self, text: str, lead: str, indent: int) -> str:
        """Crop text that would be longer than the terminal's width"""
        if self.show_all or self.no_truncate:
            return text
        total_length = len(text) + len(lead) + indent
        if total_length > self.width:
            return text[:(self.width - len(lead) - indent - 3)] + "..."
        return text

    def _print_text(self, text: str, verdict: str, lead: str, writer: TextIO,
                    indent: int=17, use_bold: bool=False) -> None:
        """Prints a cropped version of given text. Adds color if verdict is given"""
        text = self._crop_text(text, lead, indent)
        if verdict:
            color = self.get_verdict_color(verdict)
            if use_bold:
                text = self.bold + text
            writer.write(
                f"{color}{'[' + verdict + ']':<{indent}}{self.reset}{lead}{color}{text}{self.reset}\n"
            )
        else:
            writer.write(f"{'':<{indent}}{lead}{text}\n")

    def _get_sub_structure(self, entity: Union[Host, Addressable, NodeComponent]) -> Dict[str, Any]:
        """Get sub structure based on given entity"""
        return {
            "srcs": self._get_sources(entity),
            "verdict": entity.status_string(),
            "address": self._get_addresses(entity) if isinstance(entity, Host) else "",
            **self._get_properties(entity)
        }

    def build_host_structure(self, entities: List[Host]) -> Dict[str, Dict[str, Any]]:
        """Build printable host and service tree structure"""
        structure = {}

        for entity in entities:
            structure[entity.name] = self._get_sub_structure(entity)

            for child in entity.children:
                structure[entity.name][child.name] = self._get_sub_structure(child)

            for component in entity.components:
                structure[entity.name][component.name + " [Component]"] = self._get_sub_structure(component)

        return structure

    def _print_host_structure(self, level: int, structure: Dict[str, Any], writer: TextIO,
                              lead: str="", parent_has_next: bool=False) -> None:
        """Print given host and service tree structure"""
        for index, entry in enumerate(structure):
            if entry == "verdict":
                continue

            # Hosts are at level -1
            if level < 0:
                verdict = structure[entry]["verdict"]
                self._print_text(entry, verdict, "", writer, use_bold=True)
                self._print_host_structure(level+1, structure[entry], writer, "│  ", False)

            elif isinstance(structure[entry], dict):
                verdict = structure[entry]['verdict']
                symbol = "└──" if index == len(structure)-1 else "├──"
                # Strip end from lead, it will be replace by symbol
                current_lead = lead[:-3] + symbol
                text = structure[entry]["text"] if "text" in structure[entry] else entry

                if verdict:
                    self._print_text(text, verdict, current_lead, writer)
                else:
                    self._print_text(text, "", current_lead, writer)

                # Check entity relations
                parent_has_next = any(
                    (isinstance(structure[key], dict) for key in list(structure.keys())[index:] if key != entry)
                ) if level >= 1 else False
                entity_has_children = any(
                    isinstance(structure[entry][key], dict) for key in structure[entry] if key != entry
                )
                is_last_entity = index == len(structure)-1

                if not is_last_entity:
                    current_lead = lead + "│  " if entity_has_children else lead + "   "
                    self._print_host_structure(
                        level+1, structure[entry], writer, lead=current_lead, parent_has_next=parent_has_next
                    )
                else:
                    # Special handling for symbols of last entities
                    if level == 0:
                        lead = "   "
                    if entity_has_children:
                        # Remove 2nd to last "|" from lead, so symbols allign properly
                        current_lead = lead[:-3] + "   " + "│  "
                    else:
                        current_lead = lead + "   "
                    self._print_host_structure(
                        level+1, structure[entry], writer, lead=current_lead, parent_has_next=parent_has_next
                    )

            else:
                has_next_entity = any(isinstance(structure[key], dict) for key in structure)
                current_lead = lead
                if not has_next_entity:
                    if level > 1 and not parent_has_next:
                        current_lead = lead[::-1].replace('│', ' ', 1)[::-1]

                if entry == "srcs":
                    for source in structure[entry]:
                        self._print_text(f"@{source}", "", current_lead, writer)

                if entry == "address" and structure[entry]:
                    self._print_text(f"Addresses: {structure[entry]}", "", current_lead, writer)

    def get_connection_status(self, connection: Connection, cache: Dict [Entity, Verdict]) -> str:
        """Returns status string for a connection"""
        if connection.con_type == ConnectionType.LOGICAL:
            return connection.con_type.value # type: ignore[no-any-return]
        verdict = connection.get_verdict(cache)
        if verdict not in [Verdict.PASS, Verdict.FAIL]:
            return connection.status.value
        return f"{connection.status.value}/{verdict.value}"

    def build_connection_structure(self, connections: List[Connection], cache: Dict[Entity, Verdict]) -> Dict[str, Any]:
        """Build a printable tree structure out of given connections"""
        structure: Dict[str, List[Dict[str, Any]]] = {"connections": []}
        for connection in connections:
            structure["connections"].append({
                "verdict": self.get_connection_status(connection, cache),
                "source": connection.source.long_name(),
                "target": connection.target.long_name(),
                "srcs": self._get_sources(connection),
                **self._get_properties(connection)
            })
        return structure

    def _print_connection_structure(self, structure: Dict[str, Any], writer: TextIO,
                                    lead: str="", symbol: str="") -> None:
        """Print given connection tree structure"""
        verdict = structure['verdict']
        children = [key for key in structure if isinstance(structure[key], dict)]
        current_lead = lead[:-3] + symbol
        if "source" in structure:
            self._print_text(f"{structure['source']:<33}{structure['target']}", verdict, current_lead, writer)
        else:
            self._print_text(structure["text"], verdict, current_lead, writer)

        current_lead = lead + "│  " if children else lead + "   "
        for source in structure["srcs"]:
            self._print_text(f"@{source}", "", current_lead, writer)

        for child in children:
            symbol = "├──" if child != children[-1] else "└──"
            self._print_connection_structure(structure[child], writer, lead=lead + "   ", symbol=symbol)

    def print_report(self, writer: TextIO) -> None:
        """Print textual report"""
        cache: Dict[Entity, Verdict] = {}
        relevant_only = not (self.show_all or (self.show and "irrelevant" in self.show))

        hosts = [host for host in self.system.get_hosts() if host.is_relevant()]
        for host in hosts:
            host.get_verdict(cache)

        connections = self.system.get_connections(relevant_only=relevant_only)
        for connection in connections:
            connection.get_verdict(cache)

        # System level
        system_verdict = self.get_system_verdict(cache)
        self.print_title(f"{self.bold}{'Verdict:':<17}System:{self.reset}", writer, "=", "-")
        self._print_text(self.system.long_name(), system_verdict.value, "", writer, use_bold=True)
        system_properties = self._get_properties(self.system)
        if system_properties:
            self._print_host_structure(0, system_properties, writer, lead="│  ")

        # Hosts and services
        self.print_title(f"{self.bold}{'Verdict:':<17}Hosts and Services:{self.reset}", writer, "=", "-")
        host_structure = self.build_host_structure(hosts)
        self._print_host_structure(-1, host_structure, writer, "", False)

        # Connections
        self.print_title(
            f"{self.bold}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{self.reset}", writer, "=", "-"
        )

        connection_structure = self.build_connection_structure(connections, cache)
        for structure in connection_structure["connections"]:
            self._print_connection_structure(structure, writer)
