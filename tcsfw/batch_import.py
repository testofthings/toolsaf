"""Batch tool-data import"""

from ast import Set
from datetime import datetime
import json
import logging
import pathlib
import io
from typing import Dict, List, Optional, Type
from enum import StrEnum

from tcsfw.address import Addresses
from tcsfw.android_manifest_scan import AndroidManifestScan
from tcsfw.basics import ExternalActivity
from tcsfw.censys_scan import CensysScan
from tcsfw.event_interface import EventInterface
from tcsfw.har_scan import HARScan
from tcsfw.mitm_log_reader import MITMLogReader
from tcsfw.model import EvidenceNetworkSource, IoTSystem
from tcsfw.nmap_scan import NMAPScan
from tcsfw.pcap_reader import PCAPReader
from tcsfw.releases import ReleaseReader
from tcsfw.spdx_reader import SPDXReader
from tcsfw.ssh_audit_scan import SSHAuditScan
from tcsfw.testsslsh_scan import TestSSLScan
from tcsfw.tools import CheckTool, SimpleFlowTool
from tcsfw.traffic import EvidenceSource
from tcsfw.tshark_reader import TSharkReader
from tcsfw.vulnerability_reader import VulnerabilityReader
from tcsfw.web_checker import WebChecker

from tcsfw.zed_reader import ZEDReader


class BatchImporter:
    """Batch importer for importing a batch of files from a directory."""
    def __init__(self, interface: EventInterface, label_filter: 'LabelFilter' = None):
        self.interface = interface
        self.system = interface.get_system()
        self.label_filter = label_filter or LabelFilter()
        self.logger = logging.getLogger("batch_importer")

        # map file types into batch tools
        self.batch_tools: Dict[BatchFileType, Type[CheckTool]] = {
            BatchFileType.APK: AndroidManifestScan,
            BatchFileType.CENSYS: CensysScan,
            BatchFileType.HAR: HARScan,
            BatchFileType.RELEASES: ReleaseReader,
            BatchFileType.SPDX: SPDXReader,
            BatchFileType.SSH_AUDIT: SSHAuditScan,
            BatchFileType.TESTSSL: TestSSLScan,
            BatchFileType.VULNERABILITIES: VulnerabilityReader,
        }

        # collect evidence sources from visited tools
        self.evidence: Dict[str, List[EvidenceSource]] = {}

    def import_batch(self, file: pathlib.Path):
        """Import a batch of files from a directory or zip file recursively."""
        if file.is_file() and file.suffix.lower() == ".zip":
            raise NotImplementedError("Zip file import is not implemented yet.")
        if file.is_dir:
            self._import_batch(file)
        else:
            raise ValueError(f"Expected directory or ZIP as : {file.as_posix()}")

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
            else:
                info = FileMetaInfo()

            # list files/directories to process
            proc_list = []
            for child in file.iterdir():
                if child == meta_file:
                    continue
                prefix = child.name[:1]
                if prefix in {".", "_"}:
                    continue
                postfix = child.name[-1:]
                if postfix in {"~"}:
                    continue
                proc_list.append(child)

            # sort files to specified order, if any
            if info.file_load_order:
                proc_files = {f.name: f for f in proc_list}
                sorted_files = []
                for fn in info.file_load_order:
                    if fn in proc_files:
                        sorted_files.append(proc_files[fn])
                        del proc_files[fn]
                sorted_files.extend(proc_files.values())
                proc_list = sorted_files

            # filter by label
            skip_processing = not self.label_filter.filter(info.label)

            # process the files in a batch?
            as_batch = info.file_type in self.batch_tools
            if as_batch:
                self._do_process_files(proc_list, info, skip_processing)

            if not info.label:
                self.logger.info("skipping all files as no 00meta.json")

            # recursively scan the directory
            for child in proc_list:
                if info and child.is_file():
                    if as_batch or not info.label:
                        continue
                    # process the files individually
                    if not info.default_include and info.label not in self.label_filter.included:
                        self.logger.debug("skipping (default=False) %s", child.as_posix())
                        continue # skip file if not explicitly included
                    with child.open("rb") as f:
                        self._do_process(f, child, info, skip_processing)
                else:
                    self._import_batch(child)

    def _do_process(self, stream: io.BytesIO, file_path: pathlib.Path, info: 'FileMetaInfo', skip_processing: bool):
        """Process the file as stream"""
        if not skip_processing:
            self.logger.info("processing (%s) %s", info.label, file_path.as_posix())

        file_name = file_path.name
        file_ext = file_path.suffix.lower()
        try:
            reader = None
            if file_ext == ".json" and info.file_type == BatchFileType.CAPTURE:
                reader = SimpleFlowTool(self.interface.get_system())
            elif file_ext == ".pcap" and info.file_type in {BatchFileType.UNSPECIFIED, BatchFileType.CAPTURE}:
                # read flows from pcap
                reader = PCAPReader(self.interface.get_system())
            elif file_ext == ".json" and info.file_type == BatchFileType.CAPTURE_JSON:
                # read flows from JSON pcap
                reader = TSharkReader(self.interface.get_system())
            elif file_ext == ".log" and info.file_type == BatchFileType.MITMPROXY:
                # read MITM from textual log
                reader = MITMLogReader(self.interface.get_system())
            elif file_ext == ".xml" and info.file_type == BatchFileType.NMAP:
                # read NMAP from xml
                reader = NMAPScan(self.interface.get_system())
            elif file_ext == ".http" and info.file_type == BatchFileType.HTTP_MESSAGE:
                # read messages from http content file
                reader = WebChecker(self.interface.get_system())
            elif file_ext == ".json" and info.file_type == BatchFileType.ZAP:
                # read ZAP from json
                reader = ZEDReader(self.interface.get_system())

            if reader:
                ev = info.source.rename(name=reader.tool.name, base_ref=file_path.as_posix())
                # tool-specific code can override, if knows better
                ev.timestamp = datetime.fromtimestamp(file_path.stat().st_mtime)
                self.evidence.setdefault(info.label, []).append(ev)
                if skip_processing:
                    self.logger.info("skipping (%s) %s", info.label, file_path.as_posix())
                    return
                reader.load_baseline = info.load_baseline
                reader.process_file(stream, file_name, self.interface, ev)
                return

        except Exception as e:
            raise ValueError(f"Error in {file_name}") from e
        self.logger.info("skipping unsupported '%s' type %s", file_name, info.file_type)

    def _do_process_files(self, files: List[pathlib.Path], info: 'FileMetaInfo', skip_processing: bool):
        """Process files"""
        tool = self.batch_tools[info.file_type](self.interface.get_system())
        tool.load_baseline = info.load_baseline

        if skip_processing:
            self.logger.info("skipping (%s) data files", info.label)
            ev = info.source.rename(name=tool.tool.name)
            self.evidence.setdefault(info.label, []).append(ev)
            return

        unmapped = set(tool.file_name_map.keys())
        for fn in files:
            if not fn.is_file():
                continue  # directories called later
            ev = info.source.rename(name=tool.tool.name, base_ref=fn.as_posix())
            self.evidence.setdefault(info.label, []).append(ev)
            with fn.open("rb") as f:
                # tool-specific code can override, if knows better
                ev.timestamp = datetime.fromtimestamp(fn.stat().st_mtime)
                done = tool.process_file(f, fn.name, self.interface, ev)
            if done:
                unmapped.remove(fn.name)
            else:
                self.logger.info("unprocessed (%s) file %s", info.label, fn.as_posix())
        if unmapped:
            self.logger.debug("no files for %s", sorted(unmapped))


class BatchFileType(StrEnum):
    """Batch file type"""
    UNSPECIFIED = "unspecified"
    APK = "apk"
    CAPTURE = "capture"
    CAPTURE_JSON = "capture-json"
    CENSYS = "censys"
    HAR = "har"
    MITMPROXY = "mitmproxy"
    NMAP = "nmap"
    RELEASES = "github-releases"  # Github format
    SPDX = "spdx"
    SSH_AUDIT = "ssh-audit"
    TESTSSL = "testssl"
    VULNERABILITIES = "blackduck-vulnerabilities"  # BlackDuck csv output
    HTTP_MESSAGE = "http"
    ZAP = "zap"  # ZED Attack Proxy

    @classmethod
    def parse(cls, value: Optional[str]):
        """Parse from string"""
        if not value:
            return cls.UNSPECIFIED
        for t in cls:
            if t.value == value:
                return t
        raise ValueError(f"Unknown batch file type: {value}")


class FileMetaInfo:
    """Batch file information."""
    def __init__(self, label="", file_type=BatchFileType.UNSPECIFIED):
        self.label = label
        self.file_load_order: List[str] = []
        self.file_type = file_type
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
        file_type = BatchFileType.parse(json_data.get("file_type")).value
        r = cls(label, file_type)
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
