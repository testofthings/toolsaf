"""Batch tool-data import"""

from ast import Set
from datetime import datetime
import json
import logging
import pathlib
import io
from typing import Dict, List

from tcsfw.address import Addresses
from tcsfw.basics import ExternalActivity
from tcsfw.event_interface import EventInterface
from tcsfw.model import EvidenceNetworkSource, IoTSystem
from tcsfw.tool_finder import ToolDepiction, ToolFinder
from tcsfw.traffic import EvidenceSource


class BatchImporter:
    """Batch importer for importing a batch of files from a directory."""
    def __init__(self, interface: EventInterface, label_filter: 'LabelFilter' = None, load_baseline=False) -> None:
        self.interface = interface
        self.system = interface.get_system()
        self.label_filter = label_filter or LabelFilter()
        self.logger = logging.getLogger("batch_importer")
        self.load_baseline = load_baseline  # True to load baseline, false to check it
        self.meta_file_count = 0

        # collect evidence sources from visited tools
        self.evidence: Dict[str, List[EvidenceSource]] = {}

    def import_batch(self, file: pathlib.Path):
        """Import a batch of files from a directory or zip file recursively."""
        if file.is_dir:
            self._import_batch(file)
            if not self.meta_file_count:
                self.logger.warning("No 00meta.json files found")
        else:
            raise ValueError(f"Expected directory, got {file.as_posix()}")

    def _import_batch(self, file: pathlib.Path):
        """Import a batch of files from a directory or zip file recursively."""
        self.logger.info("scanning %s", file.as_posix())
        if file.is_dir():
            dir_name = file.name
            meta_file = file / "00meta.json"
            if meta_file.is_file():
                # the directory has data files
                if meta_file.stat().st_size == 0:
                    info = FileMetaInfo(dir_name) # meta_file is empty
                else:
                    try:
                        with meta_file.open("rb") as f:
                            info = FileMetaInfo.parse_from_stream(f, dir_name, self.system)
                    except Exception as e:
                        raise ValueError(f"Error in {meta_file.as_posix()}") from e
                self.evidence.setdefault(info.label, [])
                self.meta_file_count += 1
            else:
                info = FileMetaInfo()

            # get tool info by file type
            tool_dep = ToolFinder.by_file_type(info.file_type)

            # list files/directories to process, files first
            proc_list = []
            for a_file in sorted(file.iterdir(), key=lambda f: (f.is_dir(), f.name)):
                if a_file == meta_file:
                    continue
                prefix = a_file.name[:1]
                if prefix in {".", "_"}:
                    continue
                postfix = a_file.name[-1:]
                if postfix in {"~"}:
                    continue
                proc_list.append(a_file)

            # sort files to specified order, if any
            if info.file_load_order:
                proc_list = FileMetaInfo.sort_load_order(proc_list, info.file_load_order)

            # filter by label
            skip_processing = not self.label_filter.filter(info.label)

            # give all files to the tool
            all_files = tool_dep.filter_files_itself()
            if all_files:
                # process all files by one tool
                self._do_process_files(proc_list, info, tool_dep, skip_processing)

            if not info.label:
                self.logger.info("skipping all files as no 00meta.json")

            # recursively scan the directory
            for a_file in proc_list:
                if info and a_file.is_file():
                    if all_files or not info.label:
                        continue
                    # process the files individually
                    if not info.default_include and info.label not in self.label_filter.included:
                        self.logger.debug("skipping (default=False) %s", a_file.as_posix())
                        continue # skip file if not explicitly included
                    with a_file.open("rb") as f:
                        self._do_process(f, a_file, info, tool_dep, skip_processing)
                else:
                    self._import_batch(a_file)

    def _do_process(self, stream: io.BytesIO, file_path: pathlib.Path, info: 'FileMetaInfo', tool: ToolDepiction,
                    skip_processing: bool):
        """Process a file """
        if not skip_processing:
            self.logger.info("processing (%s) %s", info.label, file_path.as_posix())

        file_name = file_path.name
        file_ext = file_path.suffix.lower()
        reader = tool.create_tool(self.system, "" if info.from_pipe else file_ext)

        try:
            if reader:
                ev = info.source.rename(name=reader.tool.name, base_ref=file_path.as_posix(),
                                        label=info.label)
                # tool-specific code can override, if knows better
                ev.timestamp = datetime.fromtimestamp(file_path.stat().st_mtime)
                self.evidence.setdefault(info.label, []).append(ev)
                if skip_processing:
                    self.logger.info("skipping (%s) %s", info.label, file_path.as_posix())
                    return
                reader.load_baseline = info.load_baseline or self.load_baseline
                reader.process_file(stream, file_name, self.interface, ev)
                return

        except Exception as e:
            raise ValueError(f"Error in {file_name}") from e
        self.logger.info("skipping unsupported '%s' type %s", file_name, info.file_type)

    def _do_process_files(self, files: List[pathlib.Path], info: 'FileMetaInfo', tool: ToolDepiction,
                          skip_processing: bool):
        """Process files"""
        reader = tool.create_tool(self.system)
        reader.load_baseline = info.load_baseline or self.load_baseline

        if skip_processing:
            self.logger.info("skipping (%s) data files", info.label)
            ev = info.source.rename(name=reader.tool.name)
            self.evidence.setdefault(info.label, []).append(ev)
            return

        unmapped = set(reader.file_name_map.keys())
        for fn in files:
            if not fn.is_file():
                continue  # directories called later
            ev = info.source.rename(name=reader.tool.name, base_ref=fn.as_posix(), label=info.label)
            self.evidence.setdefault(info.label, []).append(ev)
            with fn.open("rb") as f:
                # tool-specific code can override, if knows better
                ev.timestamp = datetime.fromtimestamp(fn.stat().st_mtime)
                done = reader.process_file(f, fn.name, self.interface, ev)
            if done:
                unmapped.remove(fn.name)
            else:
                self.logger.info("unprocessed (%s) file %s", info.label, fn.as_posix())
        if unmapped:
            self.logger.debug("no files for %s", sorted(unmapped))


class FileMetaInfo:
    """Batch file information."""
    def __init__(self, label="", file_type=""):
        self.label = label
        self.file_load_order: List[str] = []
        self.file_type = file_type
        self.from_pipe = False
        self.load_baseline = False
        self.default_include = True
        self.source = EvidenceNetworkSource(file_type)

    @classmethod
    def parse_from_stream(cls, stream: io.BytesIO, directory_name: str, system: IoTSystem) -> 'FileMetaInfo':
        """Parse from stream"""
        return cls.parse_from_json(json.load(stream), directory_name, system)

    @classmethod
    def parse_from_json(cls, json_data: Dict, directory_name: str, system: IoTSystem) -> 'FileMetaInfo':
        """Parse from JSON"""
        label = str(json_data.get("label", directory_name))
        file_type = json_data.get("file_type", "")
        r = cls(label, file_type)
        r.from_pipe = bool(json_data.get("from_pipe", False))
        r.load_baseline = bool(json_data.get("load_baseline", False))
        r.file_load_order = json_data.get("file_order", [])
        r.default_include = bool(json_data.get("include", True))

        # read batch-specific addresses
        for add, ent in json_data.get("addresses", {}).items():
            address = Addresses.parse_address(add)
            entity = system.get_entity(ent)
            if not entity:
                raise ValueError(f"Unknown entity {ent}")
            r.source.address_map[address] = entity

        # read batch-specific external activity policies
        for n, policy_n in json_data.get("external_activity", {}).items():
            node = system.get_entity(n)
            if not node:
                raise ValueError(f"Unknown entity '{n}'")
            policy = ExternalActivity[policy_n]
            r.source.activity_map[node] = policy
        return r

    @classmethod
    def sort_load_order(cls, files: List[pathlib.Path], load_order: List[str]) -> List[pathlib.Path]:
        """Sort files according to load order"""
        proc_files = {f.name: f for f in files}
        sorted_files = []
        for fn in load_order:
            if fn in proc_files:
                sorted_files.append(proc_files[fn])
                del proc_files[fn]
        sorted_files.extend(proc_files.values())
        return sorted_files

    def __repr__(self) -> str:
        return f"file_type: {self.file_type}, label: {self.label}"


class LabelFilter:
    """Filter labels"""
    def __init__(self, label_specification="") -> None:
        """Initialize the filter"""
        self.explicit_include = True
        self.included: Set[str] = set()
        self.excluded: Set[str] = set()
        spec = label_specification.strip()
        if spec == "":
            self.explicit_include = False
            return  # all included
        for index, d in enumerate(spec.split(",")):
            remove = d.startswith("^")
            if remove:
                # remove label
                if index == 0:
                    self.explicit_include = False
                self.excluded.add(d[1:])
            else:
                # include label
                self.included.add(d)
        intersect = self.included.intersection(self.excluded)
        if intersect:
            raise ValueError(f"Labels in both included and excluded: {intersect}")

    def filter(self, label: str) -> bool:
        """Filter the label"""
        if self.explicit_include:
            return label in self.included
        return label not in self.excluded
