from typing import List, Optional, Tuple, Self, Dict, Set, Callable, Iterable, Union, Any

from tcsfw.address import Protocol
from tcsfw.claim import Claim
from tcsfw.components import Software
from tcsfw.entity import Entity, ClaimStatus, ExplainableClaim, ClaimAuthority
from tcsfw.events import ReleaseInfo
from tcsfw.model import IoTSystem, Connection, Host, Service, HostType, NetworkNode
from tcsfw.property import Properties, PropertyKey, PropertyVerdictValue, PropertyVerdict, \
    PropertySetValue
from tcsfw.traffic import Tool
from tcsfw.verdict import Verdict, Verdictable


class ClaimContext:
    """The context where claim is resolved"""
    def __init__(self):
        # Property keys which tools are reported they cover
        self.tool_coverage: Dict[Entity, Dict[PropertyKey, Set[Tool]]] = {}
        # Properties read by the claims, with their values (converted to bool, when possible)
        self.properties: Dict[Tuple[Entity, Claim], Dict[PropertyKey, Any]] = {}

    def check(self, claim: 'EntityClaim', entity: Entity) -> Optional[ClaimStatus]:
        """Resolve claim results"""
        base_cs = claim.check(entity, self)  # always run the check for collecting data
        property_key = claim.get_override_key(entity)
        override = entity.properties.get(property_key)
        is_override = isinstance(override, PropertyVerdictValue)
        if is_override:
            self.properties.setdefault((entity, claim), {})[property_key] = True
            cs = ClaimStatus(claim, verdict=override.verdict, explanation=override.explanation,
                             authority=ClaimAuthority.MANUAL)
        else:
            cs = base_cs
        return cs

    def get_property_value(self, entity: Entity, claim: Claim, key: PropertyKey) -> Optional:
        """Get and test property value"""
        v = key.get(entity.properties)
        self.properties.setdefault((entity, claim), {})[key] = v  # may be null
        return v

    def get_property_verdict(self, entity: Entity, claim: Claim, key: PropertyKey,
                             properties: Dict[PropertyKey, Any]) -> Optional[Verdict]:
        """Get verdict by property"""
        v = entity.properties.get(key)
        if v is None:
            self.properties.setdefault((entity, claim), {})[key] = None
            return
        if isinstance(v, Verdictable):
            ver = v.get_verdict()
        elif isinstance(v, PropertySetValue):
            ver = v.get_overall_verdict(properties)
        else:
            assert False, f"Property '{property}' value is not verdictable"
        # remember the boolean value
        self.properties.setdefault((entity, claim), {})[key] = ver == Verdict.PASS
        return ver

    def mark_coverage(self, entity: Entity, claim: Claim, key: PropertyKey, value: Any):
        """Just mark property asked, without it being in entity"""
        kv = self.properties.setdefault((entity, claim), {})
        if key not in kv:
            kv[key] = value


class EntityClaim(ExplainableClaim):
    """Base class for entity claims"""
    def __init__(self, description=""):
        super().__init__(description)
        self.property_key: Optional[PropertyKey] = None

    def name(self, value: str) -> Self:
        """Name the claim"""
        self.description = value
        return self

    def __or__(self, other: 'EntityClaim') -> 'AlternativeClaim':
        """Alternative claims, first to pass is used"""
        return AlternativeClaim((self, other))

    def __add__(self, other: 'EntityClaim') -> 'AggregateClaim':
        """Many possible claims, at least one must pass"""
        return AggregateClaim((self, other), one_pass=True)

    def __mul__(self, other: 'EntityClaim') -> 'AggregateClaim':
        """Many possible claims, all must pass"""
        return AggregateClaim((self, other))

    def __mod__(self, name: str) -> 'Self':
        """Rename"""
        self.description = name
        return self

    def get_override_key(self, entity: Entity) -> Optional[PropertyKey]:
        """Get override key for this property / entity"""
        return self.property_key

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        """Check a claim for target entity"""
        return None

    def get_sub_claims(self) -> Iterable['EntityClaim']:
        """List possibly sub-claims"""
        return []

    @classmethod
    def get_all_claims(cls, claim: Claim) -> Set['EntityClaim']:
        """Get all stacked entity claims"""
        s = set()
        if not isinstance(claim, EntityClaim):
            return s

        def unpack(claim: EntityClaim):
            s.add(claim)
            for c in claim.get_sub_claims():
                unpack(c)
        unpack(claim)
        return s

    def assert_host(self, entity: Entity, condition: Callable[[Host], bool] = None, message="") -> Host:
        assert isinstance(entity, Host), \
            message or f"Claim '{self.description}' applies only to host, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity

    def assert_software(self, entity: Entity, condition: Callable[[Software], bool] = None, message="") -> Software:
        assert isinstance(entity, Software), \
            message or f"Claim '{self.description}' applies only to SW, not: {entity}"
        if condition:
            assert condition(entity), \
                message or f"Claim '{self.description}' condition not met for {entity}"
        return entity


class NamedClaim(EntityClaim):
    """Named claim"""
    def __init__(self, name: str, claim: EntityClaim):
        super().__init__(name)
        self.named_claim = claim

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        return context.check(self.named_claim, entity)

    def __repr__(self):
        return f"{self.description}"

    def get_sub_claims(self) -> List['EntityClaim']:
        return [self.named_claim]


class StatusClaim(EntityClaim):
    """Return entity status verdict as the verdict"""
    def __init__(self, description: str):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        if not isinstance(entity, NetworkNode) and not isinstance(entity, Connection):
            return None
        if isinstance(entity, Host):
            p = Properties.EXPECTED_HOSTS
        elif isinstance(entity, Service):
            p = Properties.EXPECTED_SERVICES
        elif isinstance(entity, Connection):
            p = Properties.EXPECTED_CONNECTIONS
        else:
            assert False, f"Unexpected entity for status claim {entity}"
        v = Properties.EXPECTED.get_verdict(entity.properties) or Verdict.INCON
        context.mark_coverage(entity, self, p, value=v == Verdict.PASS)
        return ClaimStatus(self, verdict=v, authority=ClaimAuthority.TOOL)


class ConnectionClaim(EntityClaim):
    """Base class to for connection claims"""
    def __init__(self, description="Connection"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Connection)
        return None


class HostClaim(EntityClaim):
    """Host claim"""
    def __init__(self, description="Host"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        self.assert_host(entity)
        return None


class PropertyClaim(EntityClaim):
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
        return PropertyClaim(description, key=PropertyVerdict.create(key))

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
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
            tools = context.tool_coverage.get(entity, {}).get(key)
            if not tools:
                return None  # no tool to set the value
            # Value not set
            return ClaimStatus(self, authority=ClaimAuthority.TOOL)
        val = entity.properties.get(key)
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=key.get_value_string(val))

    # NOTE: We assume that key alone separates claims

    def __eq__(self, other):
        return isinstance(other, PropertyClaim) and other.property_key == self.property_key

    def __hash__(self):
        return self.property_key.__hash__()


class AlternativeClaim(EntityClaim):
    """List of alternative claims"""
    def __init__(self, claims: tuple[EntityClaim, ...], description=""):
        super().__init__(description or (" | " .join([f"{s}" for s in claims])))
        self.sequence = claims

    def check(self, entity: Host, context: ClaimContext) -> Optional[ClaimStatus]:
        best: Optional[ClaimStatus] = None
        for c in self.sequence:
            r = context.check(c, entity)
            if r is None:
                continue
            if best is None or (best.verdict == Verdict.INCON and r.verdict != Verdict.INCON):
                best = r
            if best.verdict != Verdict.INCON:
                break
        return best

    def get_sub_claims(self) -> Tuple[EntityClaim, ...]:
        return self.sequence

    def __or__(self, other: EntityClaim) -> 'AlternativeClaim':
        """Make alternative claim"""
        return AlternativeClaim(self.sequence + (other,))

    def __eq__(self, other):
        return isinstance(other, AlternativeClaim) and other.sequence == self.sequence

    def __hash__(self):
        return hash(self.sequence)


class AggregateClaim(EntityClaim):
    """Aggregate claim made up ofsub claims"""
    def __init__(self, claims: Tuple[EntityClaim, ...], description="", one_pass=False):
        super().__init__(description or ((" + " if one_pass else " * ") .join([f"{s}" for s in claims])))
        self.sequence = claims
        self.one_pass = one_pass

    def check(self, entity: Host, context: ClaimContext) -> Optional[ClaimStatus]:
        sub = []
        for c in self.sequence:
            # visit all to collect data
            r = context.check(c, entity)
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

    def get_sub_claims(self) -> Tuple[EntityClaim]:
        return self.sequence

    def __add__(self, other: EntityClaim) -> 'AggregateClaim':
        return AggregateClaim(self.sequence + (other,), one_pass=True)

    def __mul__(self, other: EntityClaim) -> 'AggregateClaim':
        return AggregateClaim(self.sequence + (other,))

    def __eq__(self, other):
        return isinstance(other, AlternativeClaim) and other.sequence == self.sequence

    def __hash__(self):
        return hash(self.sequence)


class ServiceClaim(EntityClaim):
    """Base class for service claims"""
    def __init__(self, description="Service"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Service)
        return None


class ConnectionAsServiceClaim(EntityClaim):
    """Service claim applied to a connection target"""
    def __init__(self, service_claim: ServiceClaim):
        super().__init__(service_claim.description)
        self.sub = service_claim

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Connection)
        target = entity.target
        cl = self.sub.check(target, context)
        if cl is not None:
            cl.claim = self  # FIXME: Factory method for ClaimStatus to change the claim
        return cl

    def get_sub_claims(self) -> Tuple[EntityClaim]:
        return (self.sub, )


class InformationClaim(HostClaim):
    """Information claim, possible filtering by private info"""
    def __init__(self, private: Optional[bool] = None, pass_no_data=False, description="Information"):
        super().__init__(description)
        self.private = private
        self.pass_no_data = pass_no_data

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        # we assume that they are listed, but not checked
        entity = self.assert_host(entity)
        info = ", ".join([i.name for i in entity.information])
        exp = "Stored sensitive data: " + info if info else "No sensitive data stored"
        return ClaimStatus(self, verdict=Verdict.PASS, authority=ClaimAuthority.MANUAL, explanation=exp)


class NoUnexpectedConnections(HostClaim):
    """No unexpected connections from known hosts"""
    def __init__(self, description="No unexpected connections found"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        entity = self.assert_host(entity)
        exp_c, see_c, un_c = 0, 0, 0
        for c in entity.connections:
            if c.is_expected():
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
        context.mark_coverage(entity, self, Properties.EXPECTED_CONNECTIONS, value=ver == Verdict.PASS)
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=exp)


class SoftwareClaim(EntityClaim):
    """Host software claim"""
    def __init__(self, description="Software"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, Software)
        return None


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

    def resources(self, *key: str) -> EntityClaim:
        """Create new claim"""
        return AggregateClaim(claims=tuple([self.resource(k) for k in key]))

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        spec_key = self.property_key.append_key(self.resource_key)
        cs = self.do_check(spec_key, entity, context)  # first, use document-specific key
        if not cs:
            cs = super().check(entity, context)
        if not cs and isinstance(entity, IoTSystem) and self.resource_key in entity.online_resources:
            return ClaimStatus(self)
        return cs

    def get_base_claim(self) -> EntityClaim:
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


class NoUnexpectedServices(EntityClaim):
    """No unexpected services"""
    def __init__(self, description="No unexpected services found"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> ClaimStatus:
        assert isinstance(entity, NetworkNode)
        if entity.host_type == HostType.BROWSER:
            assert not entity.children
            # NOTE: Selector may be used to exclude
            context.mark_coverage(entity, self, Properties.EXPECTED_SERVICES, value=True)
            return ClaimStatus(self, verdict=Verdict.PASS, explanation="Browser cannot open services",
                               authority=ClaimAuthority.TOOL)
        services = [c for c in entity.children if c.is_relevant()]
        exp_c, see_c, un_c = 0, 0, 0
        for c in services:
            if c.is_expected():
                exp_c += 1
                see_c += 1 if Properties.EXPECTED.get_verdict(c.properties) == Verdict.PASS else 0
            else:
                un_c += 1
        if exp_c == 0 and un_c == 0:
            exp = "No expected services"
        else:
            exp = f"{see_c}/{exp_c} expected services"
        if un_c > 0:
            exp += f", but {un_c} unexpected ones"
        if see_c == 0 and exp_c > 0 and un_c == 0:
            ver = Verdict.INCON
        else:
            ver = Verdict.PASS if un_c == 0 else Verdict.FAIL
        context.mark_coverage(entity, self, Properties.EXPECTED_SERVICES, value=ver == Verdict.PASS)
        return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL, explanation=exp)


class AuthenticationClaim(PropertyClaim):
    """Is service authenticated"""
    def __init__(self, description="Authenticated", key=Properties.AUTHENTICATION):
        super().__init__(description, key)

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
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

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
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

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
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

    def get_override_key(self, entity: Entity) -> Optional[PropertyKey]:
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

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        key = self.get_override_key(entity)
        if key is None:
            return None  # unknown protocol
        ver = context.get_property_verdict(entity, self, key, entity.properties)
        if ver is not None:
            return ClaimStatus(self, verdict=ver, authority=ClaimAuthority.TOOL)
        if not isinstance(entity, Connection):
            return None
        # no verdict for connection - try the service
        res = self.check(entity.target, context)
        # fix also tool coverage references
        tool_cov = context.tool_coverage
        for ent, kvs in tool_cov.copy().items():
            if ent == entity.target:
                tool_cov.setdefault(entity, {}).update(kvs)
        return res


class EncryptionClaim(PropertyClaim):
    """Check that service or connection is encrypted"""
    def __init__(self, description="Strong encryption protocol chosen"):
        super().__init__(description, key=Properties.ENCRYPTION)

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
        return (isinstance(entity, NetworkNode) or isinstance(entity, Connection)) and entity.is_encrypted()


class HTTPRedirectClaim(PropertyClaim):
    """Is a service a HTTP redirection to HTTPS?"""
    def __init__(self, description="HTTP redirect to HTTPS"):
        super().__init__(description, key=Properties.HTTP_REDIRECT)

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
        return isinstance(entity, Service) and entity.protocol == Protocol.HTTP


class MITMClaim(PropertyClaim):
    """Check that connection cannot be MITMed"""
    def __init__(self, description="MITM"):
        super().__init__(description, key=Properties.MITM)

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
        return isinstance(entity, Connection) and entity.is_encrypted()


class FuzzingClaim(PropertyClaim):
    """Fuzz testing performed"""
    def __init__(self, description="Fuzz testing"):
        super().__init__(description, key=Properties.FUZZ)

    def pre_filter(self, entity: Entity, context: ClaimContext) -> bool:
        return isinstance(entity, Service)


class PermissionClaim(SoftwareClaim):
    """Claim for permissions, mobile for now"""
    def __init__(self, no_vulnerabilities=False, description: str = None):
        super().__init__("permissions are listed")

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
            # FIXME: Check the data!
            return ClaimStatus(self, verdict=Verdict.PASS, authority=ClaimAuthority.TOOL, explanation=f"{info}")
        return None


class SystemClaim(EntityClaim):
    def __init__(self, description="System"):
        super().__init__(description)

    def check(self, entity: Entity, context: ClaimContext) -> Optional[ClaimStatus]:
        assert isinstance(entity, IoTSystem)
        return None


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


class Claims:
    """Basic claims, priority order, use the first appropriate"""

    @classmethod
    def name(self, value: str, claim: EntityClaim) -> EntityClaim:
        """Give claim a name"""
        return NamedClaim(value, claim)

    @classmethod
    def any_of(cls, *claim: EntityClaim) -> EntityClaim:
        """Enough to met any of the claims"""
        return AlternativeClaim(list(claim))

    AUTOMATIC_UPDATES = UpdateClaim()                         # automatic software updates
    COOKIES_LISTED = HostClaim("Cookies are listed")          # Browser cookies listed
    WEB_BEST_PRACTICE = PropertyClaim("Web best practises", Properties.WEB_BEST)
    HTTP_REDIRECT = HTTPRedirectClaim()
    NO_UNEXPECTED_SERVICES = NoUnexpectedServices()           # no unexpected services
    PRIVATE = InformationClaim(private=True)                  # private user data or PII
    PERMISSIONS_LISTED = HostClaim("Permissions are listed")  # (Mobile) permissions listed
    DATA_CONFIRMED = PropertyClaim("Data confirmed", Properties.DATA_CONFIRMED)


PropertyLocation = Tuple[Entity, PropertyKey]
ClaimLocation = Tuple[Claim, Entity]
IdentifierLocation = Tuple[Tuple[str, str], Entity]
