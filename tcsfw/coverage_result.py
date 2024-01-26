import logging
import os
import textwrap
from typing import TextIO, Tuple, Dict, Optional, List, Set, Callable, Iterator

from tcsfw.claim_coverage import RequirementClaimMapper, ClaimMapping, RequirementStatus
from tcsfw.claim_set import ClaimContext
from tcsfw.default_requirements import DEFAULT
from tcsfw.entity import Entity, ClaimStatus, ClaimAuthority
from tcsfw.etsi_ts_103_701 import ETSI_TS_103_701, ETSI_TS_103_701_FIN
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey, Properties
from tcsfw.requirement import Specification, Requirement
from tcsfw.verdict import Verdict


class CoverageReport:
    """Report of the system status"""
    def __init__(self, system: IoTSystem, coverage: RequirementClaimMapper, details=True):
        self.system = system
        self.coverage = coverage
        self.details = details
        self.logger = logging.getLogger("report")

    @classmethod
    def load_specification(self, identifier: str) -> Specification:
        """Load specification by name"""
        if not identifier or identifier == DEFAULT.specification_id:
            return DEFAULT
        if identifier == ETSI_TS_103_701.specification_id:
            return ETSI_TS_103_701
        if identifier == ETSI_TS_103_701_FIN.specification_id:
            return ETSI_TS_103_701_FIN
        raise FileNotFoundError(f"Unknown specification '{identifier}'")

    @classmethod
    def _list_properties(cls, status: RequirementStatus) -> Dict[PropertyKey, bool]:
        """List properties resolved for a claim"""
        r = {}
        for ps in status.context.properties.values():
            for p, v in ps.items():
                r[p] = True if v else False  # boolean mapping
        return r

    def _get_mappings(self, specification: Specification) -> ClaimMapping:
        return self.coverage.map_claims(specification)

    def print_summary(self, writer: TextIO, specification: Specification, name: str):
        """Print coverage summary"""
        pri = specification.cutoff_priority
        if "_" in name:
            name, _, ps= name.rpartition("_")
            pri = int(ps)
        if name == "reqs":
            self._print_by_requirements(writer, specification, priority=pri)
        elif name == "stats":
            self._print_statistics(writer, specification)
        elif not name:
            self._print_coverage(writer, specification)
        else:
            raise Exception(f"No such coverage info '{name}'")

    def _print_coverage(self, writer: TextIO, specification: Specification):
        mapping = self._get_mappings(specification)
        sections = mapping.get_entities_by_sections()

        for sec, ents in sections.items():
            writer.write(f"== {sec} ===\n")
            for entity, rs in ents.items():
                writer.write(f"{entity.long_name()}\n")
                tool_cov = self.coverage.tool_coverage.get(entity, {})
                for req, stat in rs.items():
                    mark = self._status_marker(stat.result)
                    props = self._list_properties(stat)
                    writer.write(f"  [{mark}] {req.identifier_string()} ({stat.result.verdict.value})\n")
                    exp = stat.result.get_explanation()
                    lines = "\n".join(textwrap.wrap(exp, 80, replace_whitespace=False))
                    lines = lines.replace("\n", "\n      ")
                    writer.write(f"      {lines}\n")
                    prop_s = []
                    for k, v in props.items():
                        k_tools = tool_cov.get(k, set())
                        tool_s = ", ".join([t.name for t in k_tools])
                        prop_s.append(("[x] " if v else "[ ] ") + f"{k}" + (f" ({tool_s})" if tool_s else ""))
                    if prop_s:
                        writer.write(f"      " + " ".join(prop_s) + "\n")

    def _print_statistics(self, writer: TextIO, specification: Specification):
        mapping = self._get_mappings(specification)

        columns = {Verdict.PASS: 0, Verdict.FAIL: 1, Verdict.INCON: 2, Verdict.IGNORE: 3}
        verdicts: Dict[str, Dict[str, List[Set[int]]]] = {
            "ui+": {},
            "def": {},
        }
        properties: Dict[str, Dict[str, Dict[Requirement, Set[str]]]] = {
            "ui+": {},
            "def": {},
        }

        for req, er in mapping.get_by_requirements().items():
            props: Dict[PropertyKey, bool] = {}
            ver = None
            for ent, stat in er.items():
                props.update(self._list_properties(stat))
                ver = Verdict.aggregate(ver, stat.result.verdict)
            target = req.selector.get_name()
            flags = sorted(Properties.get_flags(props))
            flag = "ui+" if flags else "def"
            ds = verdicts[flag]
            v_col = ds.get(target)
            if not v_col:
                v_col = ds[target] = [set() for _ in range(0, len(columns))]
            v_col[columns[ver]].add(req)
            p_set = properties[flag].setdefault(target, {})
            pp_set = p_set.setdefault(req, set())
            for p in props.keys():
                pn = p.get_name()
                pp_set.add(pn[6:] if pn.startswith("check:") else pn)  # remove the obvious prefix

        def print_set(value: Tuple[str, ...]) -> str:
            return ",".join(value)

        writer.write("== Requirement statistics ==\n")
        writer.write(f"  {'':<10} Pass Fail Nots Unde Igno  +++\n")
        for flag, fs in verdicts.items():
            writer.write(f"Flag {flag}\n")
            c_sum = [0] * (len(columns) + 1)
            for target, ts in fs.items():
                f_sum = 0
                for f in range(0, len(columns)):
                    c_sum[f] += len(ts[f])
                    f_sum += len(ts[f])
                vals = [f"{len(v):>4}" for v in ts]
                vals.append(f"{f_sum:>4}")

                t_props = properties[flag].get(target, [])
                ps_counts: Dict[Tuple[str, ...], int] = {}
                ps_count_tot = 0
                for p_set in t_props.values():
                    p_key = tuple(sorted(p_set))
                    ps_counts[p_key] = ps_counts.get(p_key, 0) + 1
                    ps_count_tot += 1
                ps_str = " ".join([f"{v}({print_set(k)})" for k, v in ps_counts.items()])

                writer.write(f"  {target:<10} {' '.join(vals)}  {ps_str}\n")
                c_sum[-1] += f_sum

                # assert f_sum == ps_count_tot, f"Req counts {f_sum} != {ps_count_tot}"

            writer.write(f"  {'':<10} {'---- ' * (len(columns) + 1)}\n")
            sums = [f"{s:>4}" for s in c_sum]
            writer.write(f"  {'':<10} {' '.join(sums)}\n")

    def _print_by_requirements(self, writer: TextIO, specification: Specification, priority: int):
        """Print coverage by requirements"""
        try:
            width = os.get_terminal_size(0).columns
        except OSError:
            width = 80

        mapping = self._get_mappings(specification)
        results_by_req = mapping.get_by_requirements()
        covered: Dict[str, Tuple[int, int]] = {}
        for r in specification.requirement_map.values():
            if r.priority < priority:
                continue

            results_by_ent = results_by_req.get(r, {})
            ent_lines: List[str] = []
            cov_c = 0
            for ent, stat in results_by_ent.items():
                cs = stat.result
                ps = self._list_properties(stat)
                flags = Properties.get_flags(ps)
                if flags:
                    assert len(flags) == 1, f"Multiple flags for {r.identifier_string()} {ent.long_name()}"
                cs_ps = set(flags)
                tool_cov = self.coverage.tool_coverage.get(ent, {})
                for p in ps.keys():
                    cs_ps.update([t.name for t in tool_cov.get(p, ())])

                ent_alias = mapping.aliases.get((r, ent, cs.claim))
                s_name = f"{ent.long_name()} ({ent_alias})" if ent_alias else ent.long_name()
                css = []
                for p in sorted(ps.keys()):
                    p_tools = tool_cov.get(p)
                    if p_tools:
                        pt_names = ",".join([t.name for t in sorted(p_tools)])
                        css.append(f"{p.get_name()} ({pt_names})")
                    else:
                        css.append(p.get_name())
                if cs.verdict in {Verdict.PASS, Verdict}:
                    cov_c += 1
                m = self._status_marker(cs)
                ent_lines.append(f"[{m}] {s_name}: {','.join(css)}")

            r_covered = cov_c == len(results_by_ent)  # the requirement covered?
            flags = Properties.get_flags(r.properties)
            if flags:
                assert len(flags) == 1, f"Multiple flags for {r.identifier_string()}"
            flag = list(flags)[0] if flags else "oth"
            old = covered.get(flag, (0, 0))
            covered[flag] = old[0] + (1 if r_covered else 0), old[1] + 1

            writer.write(f"Req {r.identifier_string(tail_only=True)} flag={flag}")
            writer.write(f" cov={cov_c / len(results_by_ent) * 100:.0f}")
            writer.write(f" sel={r.selector.get_name()} claim={r.claim.get_base_claim().text()}")
            writer.write("\n")
            for li in ent_lines:
                writer.write(f"  {li}\n")

            text = "\n  ".join(textwrap.wrap(f"{r.text}", width=width - 4))
            writer.write(f"  {text}\n")

            writer.write("\n")

        writer.write("Coverage summary:\n")
        for n, counts in covered.items():
            cc, c = counts
            writer.write(f"  {n:<4} {cc / c * 100:.0f}% {cc}/{c}\n")

    def _status_marker(cls, status: Optional[ClaimStatus]) -> str:
        if status is None:
            return "."
        if status.verdict == Verdict.INCON:
            return "?"
        if status.verdict != Verdict.PASS:
            return "!"
        if status.authority in {ClaimAuthority.MODEL, ClaimAuthority.TOOL}:
            return "X"  # actually verified!
        return "x"

    @classmethod
    def _light(self, verdict: Verdict) -> str:
        """Verdict traffic light"""
        if verdict in {Verdict.IGNORE, Verdict.INCON}:
            return "yellow"
        if verdict == Verdict.PASS:
            return "green"
        return "red"

    @classmethod
    def _update_verdict(self, base: Verdict, verdict: Optional[Verdict]) -> Verdict:
        """Update aggregate verdict"""
        if verdict is None:
            return base
        if base == Verdict.INCON or verdict == Verdict.INCON:
            return Verdict.INCON
        else:
            return Verdict.aggregate(base, verdict)

    def _get_properties(self, status: RequirementStatus) -> Dict[PropertyKey, Dict]:
        """Get properties resolved for a claim"""
        r = {}
        for key, ps in status.context.properties.items():
            ent, claim = key
            tool_cov = self.coverage.tool_coverage.get(ent, {})
            for p, v in ps.items():
                tools = sorted(tool_cov.get(p, []))
                r[p] = {
                    "value": True if v else False,  # boolean value
                    "tools": [t.name for t in tools],
                }
        return r

    def _create_coverage(self, specification: Specification) -> Dict:
        """Create coverage information JSON output"""
        root = {
            "specification": specification.specification_id,
            "specification_name": specification.specification_name
        }
        sections = root["sections"] = []

        mapping = self._get_mappings(specification)

        sec_ent: Dict[str, List[Entity]] = {}
        sec_map: Dict[str, Dict[Requirement, Dict[Entity, RequirementStatus]]] = {}
        for sec, reqs in mapping.get_entities_by_sections().items():
            cols = sec_ent[sec] = []
            r_map = sec_map[sec] = {}
            for ent, stat in reqs.items():
                cols.append(ent)
                for req, st in stat.items():
                    r_map.setdefault(req, {})[ent] = st

        ignore_len_name = f"Tool {Verdict.IGNORE.value}"
        legend = {
            f"": "Total coverage locations",
            f"Tool {Verdict.PASS.value}": "Verification pass",
            f"Tool {Verdict.FAIL.value}": "Verification fail",
            ignore_len_name: "Not relevant",
            f"Tool {Verdict.INCON.value}": "Not verified",
            f"Manual {Verdict.PASS.value}": "Explained pass",
            f"Manual {Verdict.IGNORE.value}": "Explained not relevant",
        }
        legend_c = {n: 0 for n in legend.keys()}

        for sec_title, req_map in sec_map.items():
            cols: List[Entity] = sec_ent[sec_title]
            col_set = set(cols)
            sec = {
                "name": sec_title,
            }
            sec_cols = sec["columns"] = []
            for c in cols:
                sec_cols.append({"name": c.long_name()})

            def status_data(status: Optional[ClaimStatus]) -> Tuple[str, Verdict]:
                if status:
                    aut = status.authority.value
                    if status.verdict != Verdict.FAIL and status.authority == ClaimAuthority.MODEL:
                        # Model can only FAIL or be inconclusive
                        verdict = Verdict.INCON
                    else:
                        verdict = Verdict.FAIL if status.verdict in {Verdict.UNEXPECTED, Verdict.MISSING} else \
                            status.verdict
                else:
                    # location is not relevant
                    aut = ClaimAuthority.TOOL.value  # nothing defined
                    verdict = Verdict.IGNORE
                return aut, verdict

            req_sorter = specification.get_sorting_key()

            sec_verdict = Verdict.PASS  # section verdict
            col_verdict = [Verdict.PASS] * len(cols)  # column (concept) verdicts
            rows = sec["rows"] = []
            for req, req_stats in sorted(req_map.items(), key=lambda kv: req_sorter(kv[0])):
                if req.priority < specification.cutoff_priority:
                    continue  # quick hack
                if not col_set.intersection(req_stats.keys()):
                    continue
                spec, ide = req.identifier
                row_data = {
                    "spec": spec,
                    "id": ide,
                    "text": req.get_text(with_identifier=False),
                }
                s_info = specification.get_short_info(req)
                row_data["short"] = s_info or ide
                col_data = row_data["columns"] = []
                row_verdict = Verdict.PASS
                for ci, c in enumerate(cols):
                    req_stat = req_stats.get(c)
                    props = self._get_properties(req_stat) if req_stat else {}
                    status = req_stat.result if req_stat else None
                    aut, verdict = status_data(status)
                    state_name = f"{aut} {verdict.value}"
                    break_d = []
                    if status:
                        for ss in status.aggregate_of:
                            ss_aut, ss_verdict = status_data(ss)
                            ss_name = f"{ss_aut} {ss_verdict.value}"
                            break_d.append(ss_name)
                    if not break_d:
                        break_d.append(state_name)
                    legend_c[state_name] = legend_c.get(state_name, 0) + 1
                    flags = set()
                    if verdict != Verdict.IGNORE:
                        flags = Properties.get_flags(props)
                    ci_data = {
                        "name": c.long_name(),
                        "state_name": state_name,
                        "verdict": verdict.value,
                        "light": self._light(verdict),
                        "description":
                            "Not a relevant requirement here" if status is None else status.get_explanation(),
                        "checks": break_d,
                        "flags": sorted(flags),
                        "properties": {f"{k}": v for k, v in props.items()},
                    }
                    col_data.append(ci_data)
                    sec_verdict = self._update_verdict(sec_verdict, verdict)
                    row_verdict = self._update_verdict(row_verdict, verdict)
                    col_verdict[ci] = self._update_verdict(col_verdict[ci], verdict)
                row_data["row_verdict"] = row_verdict.value
                row_data["row_light"] = self._light(row_verdict)
                rows.append(row_data)
            # update column data
            for ci, cv in enumerate(col_verdict):
                sec_cols[ci]["column_verdict"] = cv.value
                sec_cols[ci]["column_light"] = self._light(cv)
            sections.append(sec)
            sec["section_verdict"] = sec_verdict.value
            sec["section_light"] = self._light(sec_verdict)

        legend_c[""] = sum([s for n, s in legend_c.items() if n != ignore_len_name])
        leg = root["legend"] = {}
        for leg_name, leg_c in legend_c.items():
            leg[leg_name] = {
                "state_name": leg_name,
                "count": leg_c,
                "description": legend.get(leg_name, "")
            }
        return root

    def json(self, specification: Specification) -> Dict:
        """Give JSON tabular output"""
        return self._create_coverage(specification)
