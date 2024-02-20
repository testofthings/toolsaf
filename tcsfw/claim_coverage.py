import logging
from typing import Dict, Set, List, Tuple

from tcsfw.claim import Claim
from tcsfw.claim_set import EntityClaim, ClaimContext
from tcsfw.entity import Entity, ClaimStatus, ClaimAuthority
from tcsfw.model import IoTSystem
from tcsfw.property import PropertyKey
from tcsfw.requirement import Specification, Requirement, SelectorContext
from tcsfw.selector import RequirementSelector
from tcsfw.traffic import Tool
from tcsfw.verdict import Verdict


class RequirementStatus:
    """Requirement status after mapping"""
    def __init__(self, requirement: Requirement, context: ClaimContext, result: ClaimStatus):
        self.requirement = requirement
        self.context = context
        self.result = result

    def __repr__(self):
        return f"{self.requirement.identifier_string()} {self.result}"


class ClaimMapping:
    """Claim mapping"""
    def __init__(self, specification: Specification):
        self.specification = specification
        self.results: Dict[Entity, Dict[Requirement, RequirementStatus]] = {}
        self.aliases: Dict[Tuple[Requirement, Entity, Claim], str] = {}

    def get_section(self, entity: Entity, requirement: Requirement) -> str:
        """Get section for an entity and requirement"""
        return self.DefaultSections.get(entity.concept_name, entity.concept_name)

    # Default sections
    DefaultSections = {
        "system": "System",
        "node": "Network nodes",
        "software": "Software",
        "data": "Critical data",
        "service": "Services",
        "connection": "Connections",
    }

    def get_entities_by_sections(self) -> Dict[str, Dict[Entity, Dict[Requirement, RequirementStatus]]]:
        """Get requirement and claim statuses by section."""

        # sort entities i.e. columns
        entity_order = {
            "system": -5,
            "node": -4,
            "service": -3,
            "connection": 1,  # last
        }
        entities = sorted(self.results.items(), key=lambda kv: entity_order.get(kv[0].concept_name, 0))

        sr = {}
        for sn in self.specification.custom_sections:
            sr[sn] = {}
        if self.specification.default_sections:
            # Default sections by entity
            if not self.specification.custom_sections:
                for sec_name in self.DefaultSections.values():
                    sr[sec_name] = {}  # all default sections present
            for ent, rc in entities:
                sec_name = self.DefaultSections.get(ent.concept_name, ent.concept_name)
                sec = sr.setdefault(sec_name, {})
                for req, st in rc.items():
                    sec.setdefault(ent, {})[req] = st
        else:
            # Sections by requirements
            for ent, rc in entities:
                for req, st in rc.items():
                    if req.priority < self.specification.cutoff_priority:
                        continue
                    sec_name = req.section_name
                    assert sec_name, f"Missing section name for {req}"
                    sec = sr.setdefault(sec_name, {})
                    sec.setdefault(ent, {})[req] = st
        return sr

    def get_by_requirements(self) -> Dict[Requirement, Dict[Entity, RequirementStatus]]:
        """Get data by requirements"""
        sr = {}
        for e, rs in self.results.items():
            for r, s in rs.items():
                sr.setdefault(r, {})[e] = s
        return sr


class RequirementClaimMapper:
    """Map requirements into claims and verdicts"""
    def __init__(self, system: IoTSystem):
        self.logger = logging.getLogger("claims")
        self.system = system
        # max. coverage by introduced tools
        self.tool_coverage: Dict[Entity, Dict[PropertyKey, Set[Tool]]] = {}

    def map_claims(self, specification: Specification) -> ClaimMapping:
        """Map claims and verdicts"""
        mapping = ClaimMapping(specification)
        selector_ctx = specification.get_entity_selector(self.system)

        requirements = specification.list_requirements()
        for r in requirements:
            self._check_claim(r, self.system, selector_ctx, mapping)

        selection = []
        for e, css in mapping.results.items():
            for r, rs in css.items():
                selection.append((r, e, rs.result.claim))
        mapping.aliases = specification.create_aliases(selection)
        return mapping

    def _check_claim(self, requirement: Requirement, entity: Entity, selector: SelectorContext, mapping: ClaimMapping):
        """Check a claim for entity, if relevant"""
        claim = requirement.claim
        assert isinstance(claim, EntityClaim), f"Unexpected claim type: {claim}"

        ent = requirement.selector.select(entity, selector)
        for e in ent:
            ctx = ClaimContext()
            ctx.tool_coverage = self.tool_coverage
            cs = ctx.check(claim, e)
            if cs is None:
                # location defined, but no claim -> inconclusive
                cs = ClaimStatus(claim)
            assert not (cs.verdict == Verdict.IGNORE and cs.authority == ClaimAuthority.TOOL), \
                f"Tool assigned ignore not wanted from claim (should de-select): {cs}"
            rs = RequirementStatus(requirement, ctx, cs)
            mapping.results.setdefault(e, {})[requirement] = rs
