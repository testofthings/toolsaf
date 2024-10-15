"""The set of available claims"""

from typing import List, Optional, Tuple, Self, Dict, Set, Callable, Iterable, Union, Any

from tdsaf.core.address import Protocol
from tdsaf.core.basics import HostType
from tdsaf.core.claim import AbstractClaim
from tdsaf.components import DataReference, Software
from tdsaf.core.entity import Entity, ClaimStatus, ExplainableClaim, ClaimAuthority
from tdsaf.core.release_info import ReleaseInfo
from tdsaf.model import IoTSystem, Connection, Host, Service, NetworkNode
from tdsaf.core.property import Properties, PropertyKey, PropertyVerdictValue, \
    PropertySetValue
from tdsaf.core.verdict import Verdict, Verdictable


class ClaimContext:
    """The context where a claim is resolved"""
    def __init__(self):
        # Properties read by the claims, with their values (converted to bool, when possible)
        self.properties: Dict[Tuple[Entity, AbstractClaim], Dict[PropertyKey, Any]] = {}

    def check(self, claim: 'RequirementClaim', entity: Entity) -> Optional[ClaimStatus]:
        """Resolve claim results"""
        base_cs = claim.check(entity, self)  # always run the check for collecting data
        manual_key = claim.get_override_key(entity)
        manual_val = entity.properties.get(manual_key) # the value may not match the PropertyKey expectations
        if manual_key:
            self.mark_coverage(entity, claim, manual_key, value=manual_val)
        is_manual = isinstance(manual_val, PropertyVerdictValue)
        if is_manual and manual_val.verdict != Verdict.INCON:
            # manual override for the value
            self.properties.setdefault((entity, claim), {})[manual_key] = True
            cs = ClaimStatus(claim, verdict=manual_val.verdict, explanation=manual_val.explanation,
                             authority=ClaimAuthority.MANUAL)
        else:
            cs = base_cs
        return cs

    def get_property_value(self, entity: Entity, claim: AbstractClaim, key: PropertyKey) -> Optional[Any]:
        """Get and test property value"""
        v = key.get(entity.properties)
        self.properties.setdefault((entity, claim), {})[key] = v  # may be null
        return v

    def get_property_verdict(self, entity: Entity, claim: AbstractClaim, key: PropertyKey,
                             properties: Dict[PropertyKey, Any]) -> Optional[Verdict]:
        """Get verdict by property"""
        v = entity.properties.get(key)
        if v is None:
            self.properties.setdefault((entity, claim), {})[key] = None
            return None
        if isinstance(v, Verdictable):
            ver = v.get_verdict()
        elif isinstance(v, PropertySetValue):
            ver = v.get_overall_verdict(properties)
        else:
            assert False, f"Property '{property}' value is not verdictable"
        # remember the boolean value
        self.properties.setdefault((entity, claim), {})[key] = ver == Verdict.PASS
        return ver

    def mark_coverage(self, entity: Entity, claim: AbstractClaim, key: PropertyKey, value: Any):
        """Just mark property asked, without it being in entity"""
        kv = self.properties.setdefault((entity, claim), {})
        if key not in kv:
            kv[key] = value


class RequirementClaim(ExplainableClaim):
    """A claim in requirement"""
    def __init__(self, description=""):
        super().__init__(description)
        self.property_key: Optional[PropertyKey] = None

    def name(self, value: str) -> Self:
        """Name the claim"""
        self.description = value
        return self

    def __or__(self, other: 'RequirementClaim') -> 'AlternativeClaim':
        """Alternative claims, first to pass is used"""
        return AlternativeClaim((self, other))

    def __add__(self, other: 'RequirementClaim') -> 'AggregateClaim':
        """Many possible claims, at least one must pass"""
        return AggregateClaim((self, other), one_pass=True)

    def __mul__(self, other: 'RequirementClaim') -> 'AggregateClaim':
        """Many possible claims, all must pass"""
        return AggregateClaim((self, other))

    def __mod__(self, name: str) -> 'Self':
        """Rename"""
        self.description = name
        return self

    def get_override_key(self, _entity: Entity) -> Optional[PropertyKey]:
        """Get override key for this property / entity"""
        if self.property_key is None:
            return None
        return self.property_key.prefix_key(Properties.PREFIX_MANUAL)

    def check(self, _entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        """Check a claim for target entity"""
        return None

    def get_sub_claims(self) -> Iterable['RequirementClaim']:
        """List possibly sub-claims"""
        return []

    @classmethod
    def get_all_claims(cls, claim: AbstractClaim) -> Set['RequirementClaim']:
        """Get all stacked entity claims"""
        s = set()
        if not isinstance(claim, RequirementClaim):
            return s

        def unpack(claim: RequirementClaim):
            s.add(claim)
            for c in claim.get_sub_claims():
                unpack(c)
        unpack(claim)
        return s

    def assert_system(self, entity: Entity, condition: Callable[[Host], bool] = None, message="") -> IoTSystem:
        """Assert entity is the IoT system and get it or give custom message if not"""
        assert isinstance(entity, IoTSystem), \
            message or f"Claim '{self.description}' applies only to system, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity

    def assert_host(self, entity: Entity, condition: Callable[[Host], bool] = None, message="") -> Host:
        """Assert entity is a host and get it or give custom message if not"""
        assert isinstance(entity, Host), \
            message or f"Claim '{self.description}' applies only to host, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity

    def assert_node(self, entity: Entity, condition: Callable[[Host], bool] = None, message="") -> NetworkNode:
        """Assert entity is a network node and get it or give custom message if not"""
        assert isinstance(entity, NetworkNode), \
            message or f"Claim '{self.description}' applies only to network nodes, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity

    def assert_software(self, entity: Entity, condition: Callable[[Software], bool] = None, message="") -> Software:
        """Assert entity is software and get it or give custom message if not"""
        assert isinstance(entity, Software), \
            message or f"Claim '{self.description}' applies only to SW, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity


class NamedClaim(RequirementClaim):
    """Named claim"""
    def __init__(self, name: str, claim: RequirementClaim):
        super().__init__(name)
        self.named_claim = claim

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        return context.check(self.named_claim, entity)

    def get_override_key(self, entity: Entity) -> Optional[PropertyKey]:
        return self.named_claim.get_override_key(entity)

    def __repr__(self):
        return f"{self.description}"

    def get_sub_claims(self) -> List['RequirementClaim']:
        return [self.named_claim]


class ConnectionClaim(RequirementClaim):
    """Base class to for connection claims"""
    def __init__(self, description="Connection"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Connection)


class HostClaim(RequirementClaim):
    """Host claim"""
    def __init__(self, description="Host"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        self.assert_host(entity)


class PropertyClaim(RequirementClaim):
    """Claim simple property value match"""
    def __init__(self, description: str, key: PropertyKey):
        super().__init__(description)
        self.property_key = key
        self.default_to: Optional[Verdict] = None

    @classmethod
    def custom(cls, description: str, key: Union[PropertyKey, Tuple[str, ...]]) -> 'PropertyClaim':
        """Create custom property claim"""
        if isinstance(key, PropertyKey):
            return PropertyClaim(description, key)
        return PropertyClaim(description, key=PropertyKey.create(key))

    def pre_filter(self, _entity: Entity, _context: ClaimContext) -> bool:
        """Filter before property check"""
        return True

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        if not self.pre_filter(entity, context):
            return None
        sc = self.do_check(self.property_key, entity, context)
        if sc is None and self.default_to:
            sc = ClaimStatus(self, verdict=self.default_to, authority=ClaimAuthority.TOOL)
        return sc

    def do_check(self, key: PropertyKey, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        """Do the check for any key"""
        ver = context.get_property_verdict(entity, self, key, entity.properties)
        if ver is None:
            return None
        val = entity.properties.get(key)
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=key.get_value_string(val))

    # NOTE: We assume that key alone separates claims

    def __eq__(self, other):
        return isinstance(other, PropertyClaim) and other.property_key == self.property_key

    def __hash__(self):
        return self.property_key.__hash__()


class AlternativeClaim(RequirementClaim):
    """List of alternative claims"""
    def __init__(self, claims: tuple[RequirementClaim, ...], description=""):
        super().__init__(description or (" | " .join([f"{s}" for s in claims])))
        self.sequence = claims

    def check(self, entity: Host, context: ClaimContext) -> Optional[ClaimStatus]:
        best: Optional[ClaimStatus] = None
        for c in self.sequence:
            r = context.check(c, entity)
            if r is None:
                continue
            if best is None or (best.verdict == Verdict.INCON and r.verdict != Verdict.INCON):
                best = r  # improve from inconclusive
            if best.verdict != Verdict.INCON:
                break  # verdict is set now
        return best

    def get_sub_claims(self) -> Tuple[RequirementClaim, ...]:
        return self.sequence

    def __or__(self, other: RequirementClaim) -> 'AlternativeClaim':
        """Make alternative claim"""
        return AlternativeClaim(self.sequence + (other,))

    def __eq__(self, other):
        return isinstance(other, AlternativeClaim) and other.sequence == self.sequence

    def __hash__(self):
        return hash(self.sequence)


class AggregateClaim(RequirementClaim):
    """Aggregate claim made up of sub claims"""
    def __init__(self, claims: Tuple[RequirementClaim, ...], description="", one_pass=False):
        super().__init__(description or ((" + " if one_pass else " * ") .join([f"{s}" for s in claims])))
        self.sequence = claims
        self.one_pass = one_pass

    def check(self, entity: Host, context: ClaimContext) -> Optional[ClaimStatus]:
        sub = []
        for c in self.sequence:
            # visit all to collect data
            r = context.check(c, entity)
            if r is None:
                r = ClaimStatus(c)  # inconclusive
            sub.append(r)
        ver = None
        auth = ClaimAuthority.TOOL
        for r in sub:
            if r is None:
                if self.one_pass:
                    continue
                return None
            if self.one_pass:
                ver = Verdict.update(r.verdict, ver)
            else:
                ver = Verdict.aggregate(r.verdict, ver)
            if r.authority == ClaimAuthority.MODEL:
                auth = r.authority  # the worst
            elif r.authority == ClaimAuthority.MANUAL and auth == ClaimAuthority.TOOL:
                auth = r.authority  # 2nd worst
        if ver is None:
            return None
        st = ClaimStatus(self, verdict=ver, authority=auth)
        st.aggregate_of = sub
        return st

    def get_sub_claims(self) -> Tuple[RequirementClaim]:
        return self.sequence

    def __add__(self, other: RequirementClaim) -> 'AggregateClaim':
        return AggregateClaim(self.sequence + (other,), one_pass=True)

    def __mul__(self, other: RequirementClaim) -> 'AggregateClaim':
        return AggregateClaim(self.sequence + (other,))

    def __eq__(self, other):
        return isinstance(other, AlternativeClaim) and other.sequence == self.sequence

    def __hash__(self):
        return hash(self.sequence)


class ServiceClaim(RequirementClaim):
    """Base class for service claims"""
    def __init__(self, description="Service"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Service)


class SensitiveDataClaim(PropertyClaim):
    """Sensitive data claim, possible filtering by private info"""
    def __init__(self, private: Optional[bool] = None, pass_no_data=False, description="Information"):
        super().__init__(description, Properties.DATA_CONFIRMED)
        self.private = private
        self.pass_no_data = pass_no_data

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        # we assume that they are listed, but not checked
        assert isinstance(entity, DataReference), f"Sensitive data check cannot process: {entity}"
        return super().check(entity, context)


class NoUnexpectedConnections(HostClaim):
    """No unexpected connections from known hosts"""
    def __init__(self, description="No unexpected connections found"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        entity = self.assert_host(entity)
        exp_c, see_c, un_c = 0, 0, 0
        for c in entity.connections:
            if c.get_expected_verdict() == Verdict.PASS:
                exp_c += 1
                see_c += 1 if Properties.EXPECTED.get_verdict(c.properties) == Verdict.PASS else 0
            elif c.is_relevant():
                un_c += 1
        exp = f"{see_c}/{exp_c} expected connections"
        if un_c > 0:
            exp += f", but {un_c} unexpected ones"
        if see_c == 0 and exp_c > 0 and un_c == 0:
            ver = Verdict.INCON
        else:
            ver = Verdict.PASS if un_c == 0 else Verdict.FAIL
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=exp)


class SoftwareClaim(RequirementClaim):
    """Host software claim"""
    def __init__(self, description="Software"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Software)


class AvailabilityClaim(PropertyClaim):
    """Check if a document, e.g. web page, is available"""
    def __init__(self, resource_key="undefined", key=Properties.DOCUMENT_AVAILABILITY):
        super().__init__("Availability of " + resource_key, key)
        self.resource_key = resource_key
        self.base_claim: Optional[AvailabilityClaim] = None

    def resource(self, key: str) -> 'AvailabilityClaim':
        """Create new claim"""
        c = AvailabilityClaim(key)
        c.base_claim = self.get_base_claim()
        return c

    def resources(self, *key: str) -> RequirementClaim:
        """Create new claim"""
        return AggregateClaim(claims=tuple(self.resource(k) for k in key))

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        spec_key = self.property_key.append_key(self.resource_key)
        cs = self.do_check(spec_key, entity, context)  # first, use document-specific key
        if not cs:
            cs = super().check(entity, context)
        if not cs and isinstance(entity, IoTSystem) and self.resource_key in entity.online_resources:
            return ClaimStatus(self)
        return cs

    def get_base_claim(self) -> RequirementClaim:
        return self.base_claim or self

    def __eq__(self, other):
        return isinstance(other, AvailabilityClaim) and other.property_key == self.property_key

    def __hash__(self):
        return self.property_key.__hash__() ^ self.resource_key.__hash__()


class ContentClaim(AvailabilityClaim):
    """Need to check document, web-page, etc. content"""
    def __init__(self, resource_key="undefined", review_hint="", key=Properties.DOCUMENT_CONTENT):
        super().__init__(resource_key, key)
        self.description = "Contents of " + resource_key + (f" ({review_hint})" if review_hint else "")
        self.default_to = Verdict.INCON  # someone just need to do it
        self.review_hint = review_hint

    def resource(self, key: str, review_hint="") -> 'ContentClaim':
        """Create new claim"""
        c = ContentClaim(key, review_hint)
        c.base_claim = self.get_base_claim()
        return c

    def __eq__(self, other):
        return isinstance(other, ContentClaim) and other.property_key == self.property_key

    def __hash__(self):
        return self.property_key.__hash__() ^ self.resource_key.__hash__()


class NoUnexpectedServices(RequirementClaim):
    """No unexpected services, covers also administrative services"""
    def __init__(self, description="No unexpected services found"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> ClaimStatus:
        assert isinstance(entity, NetworkNode)
        if entity.host_type == HostType.BROWSER:
            assert not entity.children
            # NOTE: Selector may be used to exclude
            return ClaimStatus(self, verdict=Verdict.PASS, explanation="Browser cannot open services",
                               authority=ClaimAuthority.TOOL)
        services = [c for c in entity.children if c.is_relevant()]
        un_exp = []
        exp_c, see_c, = 0, 0
        exp_non_admin, see_non_admin = 0, 0
        for c in services:
            non_admin = c.host_type != HostType.ADMINISTRATIVE
            if non_admin:
                exp_non_admin += 1
            c_ver = context.get_property_verdict(c, self, Properties.EXPECTED, c.properties) or Verdict.INCON
            if c_ver == Verdict.PASS:
                exp_c += 1
                see_c += 1
                if non_admin:
                    see_non_admin += 1
            elif c_ver == Verdict.INCON:
                exp_c += 1
            else:
                un_exp.append(c.name)
        exp = f"{see_non_admin}/{exp_non_admin} expected services"
        if exp_c > exp_non_admin:
            exp += f" ({see_c - see_non_admin}/{exp_c - exp_non_admin} admin services)"
        if len(un_exp) > 0:
            exp += ", unexpected: " + ", ".join(un_exp)
        if len(un_exp) > 0:
            ver = Verdict.FAIL
        if see_non_admin < exp_non_admin:
            ver = Verdict.INCON  # not all non-admin services seen
        else:
            ver = Verdict.PASS
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=exp)


class AuthenticationClaim(PropertyClaim):
    """Is service authenticated"""
    def __init__(self, description="Authenticated", key=Properties.AUTHENTICATION):
        super().__init__(description, key)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        return isinstance(entity, Service) and entity.authentication


class UpdateClaim(SoftwareClaim):
    """Claim for presence of an update channel"""
    def __init__(self, description="Update mechanism is defined"):
        super().__init__(description)
        self.property_key = PropertyKey("check", "update-mechanism")

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Software)
        if entity.entity.host_type == HostType.MOBILE:
            # mobile apps are indeed updated
            context.mark_coverage(entity, self, Properties.UPDATE_SEEN, value=True)
            return ClaimStatus(self, explanation="Mobile applications updated by mobile OS", verdict=Verdict.PASS,
                               authority=ClaimAuthority.TOOL)
        if entity.entity.host_type == HostType.BROWSER:
            # it is _downloaded_ so no update needed
            context.mark_coverage(entity, self, Properties.UPDATE_SEEN, value=True)
            return ClaimStatus(self, explanation="Browser runs latest downloaded client SW", verdict=Verdict.PASS,
                               authority=ClaimAuthority.TOOL)
        if entity.entity.host_type == HostType.REMOTE:
            # this must be confirmed
            context.mark_coverage(entity, self, Properties.UPDATE_SEEN, value=True)
            return ClaimStatus(self, explanation="Backend can be updated directly by provider", verdict=Verdict.PASS,
                               authority=ClaimAuthority.MODEL)
        # Check if updates over channel are observed
        ver = None
        for c in entity.update_connections:
            # just copy update connection verdict
            ver = Verdict.aggregate(Properties.EXPECTED.get_verdict(c.properties), ver)
        context.mark_coverage(entity, self, Properties.UPDATE_SEEN, value=ver == Verdict.PASS)
        if ver is None:
            return None
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL,
                           explanation="Update connection observed")


class UnexpectedUpdateClaim(PropertyClaim):
    """Claim for presence of an unexpected update channel"""
    def __init__(self, description="Unexpected update mechanism"):
        super().__init__(description, PropertyKey("check", "no-update-mechanism"))

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        if not isinstance(entity, Software):
            return False
        if entity.entity.host_type == HostType.MOBILE:
            # mobile apps are indeed updated
            return False
        if entity.entity.host_type == HostType.BROWSER:
            # it is _downloaded_ so no update needed
            return False
        if entity.entity.host_type == HostType.REMOTE:
            # remote does not have update channel
            return False
        return not entity.update_connections

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Software)
        if entity.update_connections:
            return ClaimStatus(self, verdict=Verdict.PASS, authority=ClaimAuthority.TOOL,
                               explanation="Update channel defined")
        return super().check(entity, context)


class BOMClaim(PropertyClaim):
    """Claim for bill of material"""
    def __init__(self, description="SBOM", key=Properties.COMPONENTS):
        super().__init__(description, key)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        # if no SW components, how can we verify anything?
        return isinstance(entity, Software) and len(entity.components) > 0


class NoVulnerabilitiesClaim(BOMClaim):
    """Claim that no vulnerabilities"""
    def __init__(self, description="No vulnerabilities", key=Properties.VULNERABILITIES):
        super().__init__(description, key)


class ProtocolClaim(ServiceClaim):
    """Check for protocol features"""
    def __init__(self, description="Protocol best practices check", tail: Optional[str] = None,
                 encrypted: Optional[bool] = None):
        super().__init__(description)
        self.property_tail = tail
        self.encrypted = encrypted

    def get_service(self, entity: Entity) -> Optional[Service]:
        """Get service, connection target is picked"""
        if isinstance(entity, Service):
            target = entity
        else:
            assert isinstance(entity, Connection)
            target = entity.target
            assert isinstance(target, Service)
        if self.encrypted is None or self.encrypted == target.is_encrypted():
            return target
        return None

    def _get_protocol_key(self, entity: Entity) -> Optional[PropertyKey]:
        """Get the property key to use"""
        s = entity
        if isinstance(entity, Connection):
            s = entity.target
        assert isinstance(s, Service)
        if s.protocol is None:
            return None
        key = Properties.PROTOCOL.append_key(s.protocol.value)
        if self.property_tail:
            key = key.append_key(self.property_tail)
        return key

    def get_override_key(self, entity: Entity) -> Optional[PropertyKey]:
        key = self._get_protocol_key(entity)
        return None if key is None else key.prefix_key(Properties.PREFIX_MANUAL)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        key = self._get_protocol_key(entity)
        if key is None:
            return None  # unknown protocol
        ver = context.get_property_verdict(entity, self, key, entity.properties)
        if ver is not None:
            return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL)
        if not isinstance(entity, Connection):
            return None
        # no verdict for connection - try the service
        res = self.check(entity.target, context)
        return res


class EncryptionClaim(PropertyClaim):
    """Check that service or connection is encrypted"""
    def __init__(self, description="Strong encryption protocol chosen"):
        super().__init__(description, key=Properties.ENCRYPTION)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        return isinstance(entity, (NetworkNode, Connection)) and entity.is_encrypted()

    def do_check(self, key: PropertyKey, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        if isinstance(entity, Connection):
            entity = entity.target  # lacking connection check tools now, we check the target
        return super().do_check(key, entity, context)

class HTTPRedirectClaim(PropertyClaim):
    """Is a service a HTTP redirection to HTTPS?"""
    def __init__(self, description="HTTP redirect to HTTPS"):
        super().__init__(description, key=Properties.HTTP_REDIRECT)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        return isinstance(entity, Service) and entity.protocol == Protocol.HTTP


class MITMClaim(PropertyClaim):
    """Check that connection cannot be MITMed"""
    def __init__(self, description="MITM"):
        super().__init__(description, key=Properties.MITM)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        return isinstance(entity, Connection) and entity.is_encrypted()


class FuzzingClaim(PropertyClaim):
    """Fuzz testing performed"""
    def __init__(self, description="Fuzz testing"):
        super().__init__(description, key=Properties.FUZZ)

    def pre_filter(self, entity: Entity, _context: ClaimContext) -> bool:
        return isinstance(entity, Service)


class PermissionClaim(SoftwareClaim):
    """Claim for permissions, mobile for now"""
    def __init__(self, description="permissions are listed"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        # only mobile now
        assert isinstance(entity, Software)
        ver = context.get_property_verdict(entity, self, Properties.PERMISSIONS, entity.properties)
        if ver is None:
            return None  # no claims
        val = entity.properties.get(Properties.PERMISSIONS)
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL,
                           explanation=Properties.PERMISSIONS.get_value_string(val))


class ReleaseClaim(SoftwareClaim):
    """Claim for presence of release history"""
    def __init__(self, description="Release history is available"):
        super().__init__(description)
        self.property_key = PropertyKey("check", "release-history")

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Software)
        info = context.get_property_value(entity, self, ReleaseInfo.PROPERTY_KEY)
        if isinstance(info, ReleaseInfo):
            # NOTE: We do not really check anything, should improve as part of making release checking real
            return ClaimStatus(self, verdict=Verdict.PASS, authority=ClaimAuthority.TOOL, explanation=f"{info}")
        return None


class SystemClaim(RequirementClaim):
    """Claim about the whole system"""
    def __init__(self, description="System"):
        super().__init__(description)

    def check(self, entity: Entity, _context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, IoTSystem)


class UserInterfaceClaim(PropertyClaim):
    """Need to manipulate user interface"""
    def __init__(self, description="User interface use and checks"):
        super().__init__(description, Properties.UI)
        self.default_to = Verdict.INCON  # 'Eihän se oo ku tekkee'


class PhysicalManipulationClaim(PropertyClaim):
    """Need to manipulate physically"""
    def __init__(self, description="Physical manipulation and checks"):
        super().__init__(description, Properties.PHYSICAL)
        self.default_to = Verdict.INCON


class Claim:
    """Claim factory"""

    @classmethod
    def expected(cls, name="Expected") -> PropertyClaim:
        """Expected entity"""
        return PropertyClaim(name, Properties.EXPECTED)

    @classmethod
    def authentication(cls, name="Authenticated") -> AuthenticationClaim:
        """Authentication claim"""
        return AuthenticationClaim(name)

    @classmethod
    def encryption(cls, name="Encryption used") -> EncryptionClaim:
        """Encryption claim"""
        return EncryptionClaim(name)

    @classmethod
    def protocol_best_practices(cls, name="Protoćol best practices used") -> ProtocolClaim:
        """Protocol best practice claim"""
        return ProtocolClaim(name)

    @classmethod
    def web_best_practices(cls, name="Web best practices") -> PropertyClaim:
        """Web best practices claim"""
        return PropertyClaim(name, Properties.WEB_BEST)

    @classmethod
    def http_redirect(cls, name="HTTP redirection") -> HTTPRedirectClaim:
        """HTTP redirection claim"""
        return HTTPRedirectClaim(name)

    @classmethod
    def updateable(cls, name="Update mechanism") -> UpdateClaim:
        """Update mechanism claim"""
        return UpdateClaim(name)

    @classmethod
    def sbom(cls, name="SBOM is accurate") -> BOMClaim:
        """SBOM claim"""
        return BOMClaim(name)

    @classmethod
    def no_vulnerabilities(cls, name="No known vulnerabilities") -> NoVulnerabilitiesClaim:
        """No vulnerabilities claim"""
        return NoVulnerabilitiesClaim(name)

    @classmethod
    def available(cls, resource_key: str) -> AvailabilityClaim:
        """Resource availability claim"""
        return AvailabilityClaim(resource_key)

    @classmethod
    def sensitive_data(cls, name="Sensitive data defined") -> SensitiveDataClaim:
        """Sensitive data claim"""
        return SensitiveDataClaim(name)

    @classmethod
    def releases(cls, name="Releases are available") -> ReleaseClaim:
        """Releases claim"""
        return ReleaseClaim(name)

    @classmethod
    def permissions(cls, name="Permissions are defined") -> PermissionClaim:
        """Mobile permission claim"""
        return PermissionClaim(name)

    @classmethod
    def name(cls, value: str, claim: RequirementClaim) -> RequirementClaim:
        """Give claim a name"""
        return NamedClaim(value, claim)

    @classmethod
    def any_of(cls, *claim: RequirementClaim) -> RequirementClaim:
        """Enough to met any of the claims"""
        return AlternativeClaim(list(claim))


PropertyLocation = Tuple[Entity, PropertyKey]
ClaimLocation = Tuple[AbstractClaim, Entity]
IdentifierLocation = Tuple[Tuple[str, str], Entity]
