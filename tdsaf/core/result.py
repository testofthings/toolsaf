"""Simple text report on the system status"""
#pylint: disable=too-many-boolean-expressions

import sys
import shutil
import logging
from functools import cached_property
from typing import TextIO, List, Dict, Tuple, Union
from colored import Fore, Style

from tdsaf.common.basics import ConnectionType
from tdsaf.common.entity import Entity
from tdsaf.common.verdict import Verdict
from tdsaf.core.model import Host, Connection, Addressable, NodeComponent
from tdsaf.common.property import Properties, PropertyKey, PropertyVerdictValue
from tdsaf.core.registry import Registry


class Report:
    """Report of the system status"""
    def __init__(self, registry: Registry):
        self.registry = registry
        self.system = registry.system
        self.source_count = 3
        self.show = []
        self.no_truncate = False
        self.c = False
        self.logger = logging.getLogger("reporter")
        self.width = self.get_terminal_width()

    @cached_property
    def use_color(self) -> bool:
        """Determines if color text should be colored"""
        return self.c or sys.stdout.isatty()

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
        w, _ = shutil.get_terminal_size(fallback=(90, 30))
        return w

    def get_system_verdict(self, cache: Dict) -> Verdict:
        """Get verdict for the entire system based on cached verdicts."""
        verdicts = cache.values()
        if Verdict.FAIL in verdicts:
            return Verdict.FAIL
        if Verdict.PASS in verdicts:
            return Verdict.PASS
        return Verdict.INCON

    def get_verdict_color(self, verdict: any) -> str:
        """Returns color value for Verdict or string"""
        if isinstance(verdict, Verdict):
            if verdict == Verdict.INCON:
                return ""
            return [self.red, self.green, self.yellow][[Verdict.FAIL, Verdict.PASS, Verdict.IGNORE].index(verdict)]
        if isinstance(verdict, str):
            verdict = verdict.lower()
            if "/" in verdict:
                v = verdict.split("/")[1]
                return [self.red, self.green, ""][["fail", "pass", "incon"].index(v)]
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
            e.event.evidence.get_reference()
            for e in self.registry.logging.get_log(entity, {key})
        ]))

        return list(sources)[:self.source_count]

    def get_properties_to_print(self, e: Union[Host, Addressable, NodeComponent, Connection]) -> List[Tuple]:
        """Retuns properties that should be printed and the number of properties"""
        prop_items = [(k,v) for k,v in e.properties.items() if k!=Properties.EXPECTED]
        if self.show_all:
            return prop_items

        result = []
        for k, v in prop_items:
            if (is_inst:=isinstance(v, PropertyVerdictValue)) and (
                v.verdict == Verdict.FAIL or
                v.verdict == Verdict.IGNORE and "ignored" in self.show or
                v.verdict != Verdict.IGNORE and "properties" in self.show
            ) or not is_inst and "properties" in self.show:
                result += [(k, v)]
        return result

    def _get_addresses(self, e: Host) -> str:
        """Get addresses for given host"""
        ads = [f"{a}" for a in sorted(e.addresses)]
        ads = [a for a in ads if a != e.name]
        return ", ".join(ads)

    def _get_text(self, k: PropertyKey, v: any) -> str:
        """Get text to print"""
        value_string = k.get_value_string(v)
        comment = k.get_explanation(v)
        comment = f" # {comment}" if comment else ""
        if isinstance(v, PropertyVerdictValue) or "=verdict" in value_string.lower():
            value_string = value_string.split("=")[0]
        return f"{value_string}{comment}"

    def _get_properties(self, entity: Union[Host, Addressable, NodeComponent, Connection],
                        parent_srcs: List=None) -> Dict:
        """Get a dictionary of properties for given entity"""
        props = {}
        k: PropertyKey
        for k, v in self.get_properties_to_print(entity):
            text = self._get_text(k, v)
            v = k.get_verdict(entity.properties)

            if (srcs:=self._get_sources(entity, k)) == parent_srcs:
                srcs = []

            props[k.get_name()] = {
                "srcs": srcs,
                "verdict": v.value if v is not None else None,
                "text": text
            }
        return props

    def _print_text(self, text: str, verdict: str, lead: str, writer: TextIO,
                    indent: int=17, use_bold: bool=False) -> None:
        """Prints a cropped version of given text. Adds color if verdict is given"""
        text = self._crop_text(text, lead, indent)
        if verdict is not None:
            color = self.get_verdict_color(verdict)
            if use_bold:
                text = self.bold + text
            writer.write(
                f"{color}{'[' + verdict + ']':<{indent}}{self.reset}{lead}{color}{text}{self.reset}\n"
            )
        else:
            writer.write(f"{'':<{indent}}{lead}{text}\n")

    def _crop_text(self, text: str, lead: str, indent: int) -> str:
        """Crop text that would be longer than the terminal's width"""
        if self.show_all or self.no_truncate:
            return text
        total_len = len(text) + len(lead) + indent
        if total_len > self.width:
            return text[:(self.width - len(lead) - indent - 3)] + "..."
        return text

    def _get_sub_structure(self, entity: Union[Host, Addressable, NodeComponent]) -> Dict:
        """Get sub structure based on given entity"""
        srcs = self._get_sources(entity)
        return {
            "srcs": srcs,
            "verdict": entity.status_string(),
            "address": self._get_addresses(entity) if isinstance(entity, Host) else None,
            **self._get_properties(entity, parent_srcs=srcs)
        }

    def build_host_structure(self, entities: List[Host]) -> Dict:
        """Build printable host and service tree structure"""
        structure = {}

        for e in entities:
            structure[e.name] = self._get_sub_structure(e)

            for c in e.children:
                structure[e.name][c.name] = self._get_sub_structure(c)

            for c in e.components:
                structure[e.name][c.name + " [Component]"] = self._get_sub_structure(c)

        return structure

    def _print_host_structure(self, lvl: int, d: Dict, writer: TextIO,
                              lead: str="", parent_has_next: bool=False) -> None:
        """Print given host and service tree structure"""
        for i, entry in enumerate(d):
            if entry == "verdict":
                continue

            # Hosts are at lvl -1
            if lvl < 0:
                v = d[entry]["verdict"]
                self._print_text(entry, v, "", writer, use_bold=True)
                self._print_host_structure(lvl+1, d[entry], writer, "│  ", False)

            elif isinstance(d[entry], dict):
                v = d[entry]['verdict']
                symbol = "└──" if i == len(d)-1 else "├──"
                # Strip end from lead, it will be replace by symbol
                c_lead = lead[:-3] + symbol
                text = d[entry]["text"] if "text" in d[entry] else entry

                if v is not None:
                    self._print_text(text, v, c_lead, writer)
                else:
                    self._print_text(text, None, c_lead, writer)

                # Check entity relations
                parent_has_next = any(
                    (isinstance(d[k], dict) for k in list(d.keys())[i:] if k != entry)
                ) if lvl>=1 else False
                entity_has_children = any(isinstance(d[entry][k], dict) for k in d[entry] if k != entry)
                is_last_entity = i == len(d)-1

                if not is_last_entity:
                    c_lead = lead + "│  " if entity_has_children else lead + "   "
                    self._print_host_structure(lvl+1, d[entry], writer, lead=c_lead, parent_has_next=parent_has_next)
                else:
                    # Special handling for symbols of last entities
                    if lvl == 0:
                        lead = "   "
                    if entity_has_children:
                        # Remove 2nd to last "|" from lead, so symbols allign properly
                        c_lead = lead[:-3] + "   " + "│  "
                    else:
                        c_lead = lead + "   "
                    self._print_host_structure(lvl+1, d[entry], writer, lead=c_lead, parent_has_next=parent_has_next)

            else:
                has_next_entity = any(isinstance(d[k], dict) for k in d)
                c_lead = lead
                if not has_next_entity:
                    if lvl > 1 and not parent_has_next:
                        c_lead = lead[::-1].replace('│', ' ', 1)[::-1]

                if entry == "srcs":
                    for src in d[entry]:
                        self._print_text(f"@{src}", None, c_lead, writer)

                if entry == "address" and d[entry] is not None:
                    self._print_text(f"Addresses: {d[entry]}", None, c_lead, writer)

    def get_connection_status(self, connection: Connection, cache: Dict) -> str:
        """Returns status string for a connection"""
        if connection.con_type == ConnectionType.LOGICAL:
            return connection.con_type.value
        v = connection.get_verdict(cache)
        if v not in [Verdict.PASS, Verdict.FAIL]:
            return connection.status.value
        return f"{connection.status.value}/{v.value}"

    def build_connecion_structure(self, connections: List[Connection], cache: Dict) -> Dict:
        """Build a printable tree structure out of given connections"""
        structure = {"connections": []}
        for c in connections:
            srcs = self._get_sources(c)
            structure["connections"].append({
                "verdict":self.get_connection_status(c, cache),
                "source": c.source.long_name(),
                "target": c.target.long_name(),
                "srcs": srcs,
                **self._get_properties(c, parent_srcs=srcs)
            })
        return structure

    def _print_connection_structure(self, d: Dict, writer: TextIO, lead: str="", symbol: str="") -> None:
        """Print given connection tree structure"""
        v = d['verdict']
        children = [k for k in d if isinstance(d[k], dict)]
        c_lead = lead[:-3] + symbol
        if "source" in d:
            self._print_text(f"{d['source']:<33}{d['target']}", v, c_lead, writer)
        else:
            self._print_text(d["text"], v, c_lead, writer)

        c_lead = lead + "│  " if children else lead + "   "
        for src in d["srcs"]:
            self._print_text(f"@{src}", None, c_lead, writer)

        for child in children:
            symbol = "├──" if child != children[-1] else "└──"
            self._print_connection_structure(d[child], writer, lead=lead + "   ", symbol=symbol)

    def print_report(self, writer: TextIO):
        """Print textual report"""
        cache: Dict[Entity, Verdict] = {}
        relevant_only = not (self.show_all or (self.show and "irrelevant" in self.show))

        hosts = [h for h in self.system.get_hosts() if h.is_relevant()]
        for h in hosts:
            h.get_verdict(cache)

        connections = self.system.get_connections(relevant_only=relevant_only)
        for c in connections:
            c.get_verdict(cache)

        # System level
        system_verdict = self.get_system_verdict(cache)
        self.print_title(f"{self.bold}{'Verdict:':<17}System:{self.reset}", writer, "=", "-")
        self._print_text(self.system.long_name(), system_verdict.value, "", writer, use_bold=True)
        system_srcs = self._get_sources(self.system)
        system_properties = self._get_properties(self.system, parent_srcs=system_srcs)
        if system_properties:
            self._print_host_structure(0, {"srcs": system_srcs}, writer, lead="│  ")
            self._print_host_structure(0, system_properties, writer, lead="│  ")

        # Hosts and services
        self.print_title(f"{self.bold}{'Verdict:':<17}Hosts and Services:{self.reset}", writer, "=", "-")
        host_structure = self.build_host_structure(hosts)
        self._print_host_structure(-1, host_structure, writer, "", False)

        # Connections
        self.print_title(
            f"{self.bold}Connections\n{'Verdict:':<17}{'Source:':<33}Target:{self.reset}", writer, "=", "-"
        )

        connection_structure = self.build_connecion_structure(connections, cache)
        for connection in connection_structure["connections"]:
            self._print_connection_structure(connection, writer)
