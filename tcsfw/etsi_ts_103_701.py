"""ETSI TS 103 701 requirements"""

import dataclasses
import os
import pathlib
import re
import textwrap
from dataclasses import dataclass
from typing import List, Dict, Optional, Iterable, Tuple, Set
from tcsfw.basics import HostType

from tcsfw.claim import AbstractClaim
from tcsfw.claim_set import RequirementClaim, AuthenticationClaim, NoUnexpectedServices, \
    AvailabilityClaim, Claim, UserInterfaceClaim, ContentClaim, \
    MITMClaim, ProtocolClaim, FuzzingClaim, PropertyClaim, \
    PhysicalManipulationClaim, NamedClaim
from tcsfw.entity import Entity
from tcsfw.model import IoTSystem, Host, Service, Connection
from tcsfw.property import Properties, PropertyKey
from tcsfw.requirement import Specification, Requirement, SelectorContext, SpecificationSelectorContext, \
    EntitySelector
from tcsfw.selector import Select, ServiceSelector, UpdateConnectionSelector, RequirementSelector


class IXIT_Section:  # pylint: disable=invalid-name
    """IXIT section definition"""
    SectionList = []

    def __init__(self, name: str, number: int, location: Optional[RequirementSelector] = None):
        self.name = name
        self.number = number
        self.location = location or EntitySelector()
        self.SectionList.append(self)

    def __repr__(self):
        return f"{self.name}-{self.number}"


DEVICE = Select.host().type_of(HostType.DEVICE)
DEVICE_UNEXPECTED = Select.host(unexpected=True).type_of(HostType.DEVICE)


class IXIT:
    """IXIT sections"""
    AuthMech = IXIT_Section("AuthMech", 1, DEVICE / Select.service().authenticated())
    UserInfo = IXIT_Section("UserInfo", 2, Select.system())
    VulnTypes = IXIT_Section("VulnTypes", 3)
    Conf = IXIT_Section("Conf", 4)
    VulnMon = IXIT_Section("VulMon", 5)
    SoftComp = IXIT_Section("SoftComp", 6, DEVICE / Select.software())
    UpdMech = IXIT_Section("UpdMech", 7, UpdateConnectionSelector())
    UpdProc = IXIT_Section("UpdProc", 8)
    ReplSup = IXIT_Section("ReplSup", 9, DEVICE)
    SecParam = IXIT_Section("SecParam", 10, Select.data())
    ComMech = IXIT_Section("ComMech", 11, Select.connection())
    NetSecImpl = IXIT_Section("NetSecImpl", 12, DEVICE / Select.software())
    SoftServ = IXIT_Section("SoftServ", 13, DEVICE / Select.service().authenticated())
    SecMgmt = IXIT_Section("SecMgmt", 14)
    Intf = IXIT_Section("Intf", 15, DEVICE_UNEXPECTED)
    CodeMin = IXIT_Section("CodeMin", 16)
    PrivlCtrl = IXIT_Section("PrivlCtrl", 17)
    AccCtrl = IXIT_Section("AccCtrl", 18)
    SecDev = IXIT_Section("SecDev", 19)
    SecBoot = IXIT_Section("SecBoot", 20, DEVICE / Select.software())
    PersData = IXIT_Section("PersData", 21, Select.data().personal())
    ExtSens = IXIT_Section("ExtSens", 22, DEVICE.with_property(Properties.SENSORS))
    ResMech = IXIT_Section("ResMech", 23, Select.system())
    TelData = IXIT_Section("TelData", 24, Select.system())
    DelFunc = IXIT_Section("DelFunc", 25, Select.system())
    UserDec = IXIT_Section("UserDec", 26, Select.system())
    UserIntf = IXIT_Section("UserIntf", 27, Select.system())
    ExtAPI = IXIT_Section("ExtAPI", 28, DEVICE / Select.service(unexpected=True))
    InpVal = IXIT_Section("InpVal", 29, DEVICE / Select.service())

    # Not from ETSI
    Generic = IXIT_Section("System*", 0, RequirementSelector())


def check(key: str | PropertyKey, description: str) -> PropertyClaim:
    """Utility to create a custom check claim"""
    return PropertyClaim.custom(description, key=("check", key) if isinstance(key, str) else key)


# Special locators
# Services which use passwords, which are not defined by the user (not detectable)
AuthMech_NotUserDefined = DEVICE / Select.service().authenticated()
# All authentication mechanism, including unexpected
AuthMech_All = DEVICE / ServiceSelector(with_unexpected=True).authenticated()
# All update connections, including unexpected
UpdMech_All = Select.connection(unexpected=True).endpoint(DEVICE)
# All communication mechanisms, including unexpected
ComMech_All = Select.connection(unexpected=True)
# Unexpected communication mechanisms after secure boot failure
SecBoot_Unexpected = Select.host().type_of(HostType.DEVICE) / Select.connection(unexpected=True)
# A physical interface (same as Intf now))
Intf_Physical = DEVICE_UNEXPECTED
# All hosts which can have ExtAPI
ExtAPI_Hosts_All = DEVICE

# Personal data (items)
UserInfo_Personal = Select.data().personal()

# Claims
UI = UserInterfaceClaim() % "UI"
PHYSICAL_MANIPULATION = PhysicalManipulationClaim() % "Physical manipulation"
CONTENT = ContentClaim() % "Document content review"

DEFINED_HOSTS_ONLY = Claim.expected("Defined hosts only")
HOST_DEFINED_SERVICES = NoUnexpectedServices() % "Defined services only"
CONNECTIONS_DEFINED_ONLY = Claim.expected("Defined connections only")
DEFINED_AUTH_ONLY = Claim.expected("Defined authentication mechanisms only")
SERVICE_BEST_PRACTICES = (Claim.web_best_practices() + Claim.protocol_best_practices()
                          + Claim.http_redirect()) % "Protocol checks"
CONNECTION = ProtocolClaim(encrypted=True) % "Defined connection mechanism"
CONN_BEST_PRACTICES = (ProtocolClaim(tail="best-practices", encrypted=True) + MITMClaim()) \
    % "Cryptographic best practices"
CONN_NO_VULNERABILITIES = ProtocolClaim(tail="no-vulnz", encrypted=True) % "No known vulnerabilities"
AVAILABILITY = AvailabilityClaim() % "Document availability"

AUTHENTICATION = AuthenticationClaim() % "Defined authentication method"
AUTH_BEST_PRACTICES = AuthenticationClaim(key=Properties.AUTH_BEST_PRACTICE) % "Use of best practices"
AUTH_NO_VULNERABILITIES = AuthenticationClaim(key=Properties.AUTH_NO_VULNERABILITIES) % "No known vulnerabilities"
AUTH_BRUTE_FORCE = AuthenticationClaim(key=Properties.AUTH_BRUTE_FORCE) % "Authentication brute-force"

ACCESS_CONTROL = AuthenticationClaim(key=Properties.AUTHENTICATION_GRANT) % "Access control"

CODE_REVIEW = check(Properties.CODE_REVIEW, "Code review performed")
CODE_SCA = check(Properties.CODE_SCA, "SCA")

SOFTWARE_CHANGE_DETECTED = check("modify-sw", "Device software modification")
SECURE_STORAGE = check("secure-storage","Storage security")
PARAMETER_CHANGED = check("param-changed", "Security parameter changed")
BASIC_SETUP = UI  # For article, we do not need basic setup, as we exclude UI tests
BASIC_FUNCTION = check("basic-function", "Basic functionality test")
ISOLATE = PropertyClaim.custom(
    "Disconnect network/power", key=("action", "isolate"))
TELEMETRY_CHECK = check("telemetry", "Telemetry data check")

VALIDATE_INPUT = (FuzzingClaim() * Claim.web_best_practices()) % "Input validation"

# 5.3.2.2 are hard to decipher, settling that a) plan custom tools, b) run standard and custom tools
UPDATE_MISUSE_DESIGN = check("mod-update", "Update mech.  misuse attacks devised")
UPDATE_MISUSE_ATTEMPT = NamedClaim("Update mech. misuse attempted", CONNECTION)
UPDATE_BEST_PRACTICES = NamedClaim("Update mech. best practices", CONN_BEST_PRACTICES)
UPDATE_NO_VULNERABILITIES = NamedClaim("Update mech., no known vulnerabilities", CONN_NO_VULNERABILITIES)

PASSWORDS_VALID = check("password-validity", "Generated password check")

REVIEW = PropertyClaim.custom("IXIT and ICS review", key=Properties.REVIEW)
CROSS_REFERENCE = PropertyClaim.custom("Cross references", key=Properties.REVIEW)


class EtsiTs103701(Specification):
    """ETSI TS 103 701 specification"""
    def __init__(self, specification_id: str, name: str, requirements: Dict[str, Requirement] = None):
        super().__init__(specification_id, name)
        self.cutoff_priority = 1

        self.test_units: Dict[str, TestUnit] = {}
        for tc in read_text_data():
            for tu in tc.units:
                self.test_units[tu.identifier()] = tu

        self.default_sections = False  # from requirements
        self.section_names = {
            "4": "Reporting implementation",
            "5.1": "No universal default passwords",
            "5.2": "Implement a means to manage reports of",
            "5.3": "Keep software updated",
            "5.4": "Securely store sensitive security parameters",
            "5.5": "Communicate securely",
            "5.6": "Minimize exposed attack surfaces",
            "5.7": "Ensure software integrity",
            "5.8": "Ensure that personal data is secure",
            "5.9": "Make systems resilient to outages",
            "5.10": "Examine system telemetry data",
            "5.11": "Make it easy for users to delete user data",
            "5.12": "Make installation and maintenance of devices",
            "5.13": "Validate input data",
            "6": "Data protection for consumer IoT",
        }
        self.custom_sections = [f"{s} {t}" for s, t in self.section_names.items()]
        self.references: Dict[str, str] = {}

        if requirements:
            self.requirement_map = requirements
            return

        # Typically, the test cases distinguish two aspects:
        # * Conceptual: Assessing conformity of the IXIT against the requirements of the provision (conformity of
        #   design); and
        # * Functional: Assessing conformity of the DUT functionality, their relation to associated services or
        #   development/management processes against the requirements of the provision (conformity of implementation).

        # Test units for functional test cases (109)

        self.make("5.1-1-2a", IXIT.AuthMech, AuthMech_All, DEFINED_AUTH_ONLY)  # UI junior partner
        self.make("5.1-1-2b", IXIT.AuthMech, claim=UI)
        self.make("5.1-1-2c", IXIT.AuthMech, AuthMech_NotUserDefined, PASSWORDS_VALID)
        self.make("5.1-2-2a", IXIT.AuthMech, AuthMech_NotUserDefined, PASSWORDS_VALID)
        self.make("5.1-3-2a", IXIT.AuthMech, claim=AUTHENTICATION)
        self.make("5.1-4-2a", IXIT.AuthMech, claim=UI)
        self.make("5.1-4-2b", IXIT.AuthMech, claim=UI)
        self.make("5.1-5-2a", IXIT.AuthMech, AuthMech_All, DEFINED_AUTH_ONLY)
        self.make("5.1-5-2b", IXIT.AuthMech, claim=AUTH_BRUTE_FORCE)
        self.make("5.2-1-2a", IXIT.UserInfo, claim=AVAILABILITY.resource("vulnerability-disclosure-policy"))
        self.make("5.2-1-2b", IXIT.UserInfo, claim=CONTENT.resource("vulnerability-disclosure-policy"))
        # In 5.3-1-2a, 5.3-2-2a, 5.3-2-2b we assume NO non-network update mechanisms
        self.make("5.3-1-2a", IXIT.SoftComp, reference="5.3-2-2")  # to UpdMech tests
        self.make("5.3-2-2a", IXIT.UpdMech, claim=UPDATE_MISUSE_DESIGN)
        self.make("5.3-2-2b", IXIT.UpdMech, claim=UPDATE_MISUSE_ATTEMPT)
        self.make("5.3-6-2a", IXIT.UpdMech, claim=CONNECTIONS_DEFINED_ONLY)
        self.make("5.3-6-2b", IXIT.UpdMech, claim=UI)
        self.make("5.3-6-2c", IXIT.UpdMech, claim=UI)
        self.make("5.3-6-2d", IXIT.UpdMech, claim=UI)
        # 5.3.10.1 Test case 5.3-10-1 (conceptual/functional)
        self.make("5.3-10-1c", IXIT.UpdMech, UpdMech_All, CONNECTIONS_DEFINED_ONLY)
        self.make("5.3-13-2a", IXIT.UserInfo, claim=AVAILABILITY.resource("published-support-period"))
        self.make("5.3-13-2b", IXIT.UserInfo, claim=AVAILABILITY.resource("published-support-period"))
        self.make("5.3-13-2c", IXIT.UserInfo, claim=CONTENT.resource("published-support-period"))
        # Using ReplSup and not UserInfo, as this is clearly replacement support and irrelevant without it
        self.make("5.3-14-2a", IXIT.ReplSup, claim=
                  AVAILABILITY.resources("not-updatable", "replacement") % AVAILABILITY.description)
        self.make("5.3-14-2b", IXIT.ReplSup, claim=
                  AVAILABILITY.resources("not-updatable", "replacement") % AVAILABILITY.description)
        self.make("5.3-14-2c", IXIT.ReplSup, claim=CONTENT.resource("not-updatable"))
        self.make("5.3-14-2d", IXIT.ReplSup, claim=CONTENT.resource("replacement"))
        self.make("5.3-14-2e", IXIT.ReplSup, claim=CONTENT.resource("not-updatable",
                                                                             "defined support period"))
        # 5.3-15-2a kind of requirement for any tests to be done :O
        self.make("5.3-15-2a", IXIT.ReplSup, claim=BASIC_SETUP)
        self.make("5.3-15-2b", IXIT.ReplSup, claim=ISOLATE)
        self.make("5.3-15-2c", IXIT.ReplSup, claim=BASIC_FUNCTION)
        self.make("5.3-15-2d", IXIT.ReplSup, claim=PHYSICAL_MANIPULATION)
        self.make("5.3-15-2e", IXIT.ReplSup, claim=BASIC_FUNCTION)
        self.make("5.3-16-2a", IXIT.UserInfo, claim=CONTENT.resource("model-designation", "available"))
        self.make("5.3-16-2b", IXIT.UserInfo, claim=CONTENT.resource("model-designation"))
        self.make("5.4-1-2a", IXIT.SecParam, claim=SECURE_STORAGE)
        self.make("5.4-2-2a", IXIT.SecParam, claim=SECURE_STORAGE)
        self.make("5.4-3-2a", IXIT.SecParam, claim=PARAMETER_CHANGED)
        self.make("5.5-1-2a", IXIT.ComMech, claim=CONNECTION)
        self.make("5.5-2-2a", IXIT.NetSecImpl, claim=CODE_SCA)
        self.make("5.5-4-2a", IXIT.SoftServ, claim=ACCESS_CONTROL)  # reject
        self.make("5.5-4-2b", IXIT.SoftServ, claim=ACCESS_CONTROL)  # grant
        self.make("5.5-4-2c", IXIT.SoftServ, claim=AUTHENTICATION)  # dupe
        self.make("5.5-5-2a", IXIT.SoftServ, reference="5.5-4-2")  # to SoftServ tests
        self.make("5.5-5-2b", IXIT.ComMech, ComMech_All, CONNECTIONS_DEFINED_ONLY)
        self.make("5.5-6-2a", IXIT.SecParam, reference="5.5-1-2")  # to CommMech tests
        self.make("5.5-7-2a", IXIT.SecParam, reference="5.5-1-2")  # to ComMech tests, remote only
        self.make("5.6-1-2a", IXIT.Intf, claim=HOST_DEFINED_SERVICES)  # also physical interfaces
        self.make("5.6-1-2b", IXIT.Intf, claim=HOST_DEFINED_SERVICES)
        self.make("5.6-2-2a", IXIT.Intf, claim=HOST_DEFINED_SERVICES)  # could also scan service best practices
        self.make("5.6-3-2a", IXIT.Intf, Intf_Physical, PHYSICAL_MANIPULATION)
        self.make("5.6-3-2b", IXIT.Intf, Intf_Physical, PHYSICAL_MANIPULATION)
        self.make("5.6-3-2c", IXIT.Intf, claim=HOST_DEFINED_SERVICES)  # only air interfaces
        self.make("5.6-3-2d", IXIT.Intf, Intf_Physical, HOST_DEFINED_SERVICES)
        self.make("5.6-4-2a", IXIT.Intf, Intf_Physical, HOST_DEFINED_SERVICES)
        self.make("5.6-4-2b", IXIT.Intf, Intf_Physical, HOST_DEFINED_SERVICES)
        self.make("5.7-1-2a", IXIT.SecBoot, claim=SOFTWARE_CHANGE_DETECTED)
        self.make("5.7-2-2a", IXIT.SecBoot, claim=UI)
        self.make("5.7-2-2b", IXIT.SecBoot, SecBoot_Unexpected, DEFINED_HOSTS_ONLY)
        self.make("5.8-1-2a", IXIT.PersData, reference="5.5-1-2")  # to ComMech tests
        self.make("5.8-2-2a", IXIT.PersData, reference="5.5-1-2")  # to ComMech tests
        # ExtSens more accurate than UserInfo
        self.make("5.8-3-1a", IXIT.ExtSens, claim=AVAILABILITY.resource("sensors"))
        self.make("5.8-3-1b", IXIT.ExtSens, claim=CONTENT.resource("sensors"))
        self.make("5.8-3-1c", IXIT.ExtSens, claim=PHYSICAL_MANIPULATION)
        self.make("5.9-1-2a", IXIT.ResMech, claim=ISOLATE)
        self.make("5.9-1-2b", IXIT.ResMech, claim=ISOLATE)
        self.make("5.9-2-2a", IXIT.ResMech, claim=BASIC_FUNCTION)
        self.make("5.9-2-2b", IXIT.ResMech, claim=BASIC_FUNCTION)
        self.make("5.9-3-2a", IXIT.ResMech, claim=ISOLATE)
        self.make("5.11-1-2a", IXIT.DelFunc, claim=BASIC_SETUP)
        self.make("5.11-1-2b", IXIT.DelFunc, claim=UI)
        self.make("5.11-1-2c", IXIT.DelFunc, claim=UI)
        self.make("5.11-2-2a", IXIT.DelFunc, claim=BASIC_SETUP)
        self.make("5.11-2-2b", IXIT.DelFunc, claim=UI)
        self.make("5.11-2-2c", IXIT.DelFunc, claim=UI)
        self.make("5.11-3-1a", IXIT.DelFunc, claim=BASIC_SETUP)
        # next two mixes content and UI claims -- assigning them bit artificially
        self.make("5.11-3-1b", IXIT.DelFunc, claim=CONTENT.resource("deletion"))
        self.make("5.11-3-1c", IXIT.DelFunc, claim=UI)
        self.make("5.11-4-1a", IXIT.DelFunc, claim=UI)
        self.make("5.11-4-1b", IXIT.DelFunc, claim=UI)  # do not leave 1 UI prioriry==0
        self.make("5.12-1-2a", IXIT.UserDec, claim=UI)
        self.make("5.12-1-2b", IXIT.UserDec, claim=UI)
        self.make("5.12-1-2c", IXIT.UserDec, claim=UI)
        self.make("5.12-1-2d", IXIT.UserDec, claim=UI)
        self.make("5.12-2-1a", IXIT.UserDec, claim=UI)
        self.make("5.12-2-1b", IXIT.UserInfo, claim=UI)
        self.make("5.12-2-1c", IXIT.UserInfo, claim=CONTENT.resource("secure-setup"))
        self.make("5.12-3-1a", IXIT.UserInfo, claim=UI)
        self.make("5.12-3-1b", IXIT.UserInfo, claim=CONTENT.resource("setup-check"))
        self.make("5.12-3-1c", IXIT.UserInfo, claim=CONTENT.resource("setup-check"))
        self.make("5.13-1-2a", IXIT.InpVal, claim=VALIDATE_INPUT)
        self.make("5.13-1-2b", IXIT.UserIntf, claim=CONTENT.resource("user-manual"))
        self.make("5.13-1-2c", IXIT.ExtAPI, ExtAPI_Hosts_All, claim=HOST_DEFINED_SERVICES)
        self.make("6-1-2a", IXIT.UserInfo, UserInfo_Personal, CONTENT.resource(
            "personal-data", "processing of the data"))
        self.make("6-1-2b", IXIT.UserInfo, UserInfo_Personal, CONTENT.resource(
            "personal-data", "match 'processing activities'"))
        self.make("6-1-2c", IXIT.UserInfo, UserInfo_Personal, CONTENT.resource(
            "personal-data", "understandable with limited technical knowledge"))
        self.make("6-1-2d", IXIT.UserInfo, UserInfo_Personal, CONTENT.resource(
            "personal-data", "how data is used and by whom"))
        self.make("6-2-2a", IXIT.UserInfo, UserInfo_Personal, UI)
        self.make("6-3-2a", IXIT.UserInfo, UserInfo_Personal, UI)
        # TelData more accurate than UserInfo
        self.make("6-5-2a", IXIT.TelData, claim=CONTENT.resource("telemetry"))
        self.make("6-5-2b", IXIT.TelData, claim=CONTENT.resource("telemetry"))
        self.make("6-5-2c", IXIT.TelData, claim=TELEMETRY_CHECK)
        self.make("6-5-2d", IXIT.TelData, claim=TELEMETRY_CHECK)

        # Test units for conceptual test cases (117)

        self.make("4-1-1a", IXIT.Generic, claim=REVIEW)
        self.make("5.1-1-1a", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-2-1a", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-2-1b", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-2-1c", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-2-1d", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-3-1a", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-3-1b", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-3-1c", IXIT.AuthMech, claim=AUTH_BEST_PRACTICES)
        self.make("5.1-3-1d", IXIT.AuthMech, claim=AUTH_NO_VULNERABILITIES)
        self.make("5.1-4-1a", IXIT.AuthMech, claim=REVIEW)
        self.make("5.1-5-1a", IXIT.AuthMech, claim=REVIEW)
        self.make("5.2-1-1a", IXIT.UserInfo, claim=REVIEW)
        self.make("5.2-2-1a", IXIT.VulnTypes, claim=REVIEW)
        self.make("5.2-2-1b", IXIT.Conf, claim=REVIEW)
        self.make("5.2-3-1a", IXIT.VulnMon, claim=REVIEW)
        self.make("5.2-3-1b", IXIT.VulnMon, claim=REVIEW)
        self.make("5.2-3-1c", IXIT.VulnMon, claim=REVIEW)
        self.make("5.2-3-1d", IXIT.VulnMon, claim=REVIEW)
        self.make("5.3-1-1a", IXIT.SoftComp, claim=REVIEW)
        self.make("5.3-1-1b", IXIT.SoftComp, reference="5.3-2-1")
        self.make("5.3-2-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-3-1a", IXIT.SoftComp, claim=REVIEW)
        self.make("5.3-4-1a", IXIT.SoftComp, claim=REVIEW)
        self.make("5.3-4-1b", IXIT.SoftComp, claim=REVIEW)
        self.make("5.3-5-1a", IXIT.SoftComp, claim=REVIEW)
        self.make("5.3-6-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-6-1b", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-6-1c", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-6-1d", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-6-1e", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-7-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-7-1b", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-7-1c", IXIT.UpdMech, claim=UPDATE_BEST_PRACTICES)
        self.make("5.3-7-1d", IXIT.UpdMech, claim=UPDATE_NO_VULNERABILITIES)
        self.make("5.3-8-1a", IXIT.UpdProc, claim=REVIEW)  # release history?
        self.make("5.3-8-1b", IXIT.Conf, claim=REVIEW)
        self.make("5.3-9-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-9-1b", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-9-1c", IXIT.UpdMech, claim=UPDATE_MISUSE_DESIGN)
        self.make("5.3-9-1d", IXIT.UpdMech, claim=UPDATE_MISUSE_DESIGN)
        # 5.3.10.1 Test case 5.3-10-1 (conceptual/functional)
        self.make("5.3-10-1a", IXIT.UpdMech, reference="5.3-9-1")
        self.make("5.3-10-1b", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-11-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-11-1b", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-12-1a", IXIT.UpdMech, claim=REVIEW)
        self.make("5.3-13-1a", IXIT.UserInfo, claim=REVIEW)
        self.make("5.3-14-1a", IXIT.UserInfo, claim=REVIEW)
        self.make("5.3-15-1a", IXIT.ReplSup, claim=REVIEW)
        self.make("5.3-15-1b", IXIT.ReplSup, claim=REVIEW)
        self.make("5.3-16-1a", IXIT.UserInfo, claim=REVIEW)
        self.make("5.4-1-1a", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-1-1b", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-1-1c", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-1-1d", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-2-1a", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-2-1b", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-2-1c", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-3-1a", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-3-1b", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-4-1a", IXIT.SecParam, claim=REVIEW)
        self.make("5.4-4-1b", IXIT.SecParam, claim=REVIEW)
        self.make("5.5-1-1a", IXIT.ComMech, claim=REVIEW)
        self.make("5.5-1-1b", IXIT.ComMech, claim=REVIEW)
        self.make("5.5-1-1c", IXIT.ComMech, claim=CONN_BEST_PRACTICES)
        self.make("5.5-1-1d", IXIT.ComMech, claim=CONN_NO_VULNERABILITIES)
        self.make("5.5-2-1a", IXIT.NetSecImpl, claim=CODE_REVIEW)
        self.make("5.5-2-1b", IXIT.NetSecImpl, claim=CODE_REVIEW)
        self.make("5.5-3-1a", IXIT.SoftComp, claim=REVIEW)
        self.make("5.5-3-1b", IXIT.SoftComp, claim=REVIEW)
        self.make("5.5-4-1a", IXIT.SoftServ, claim=REVIEW)
        self.make("5.5-4-1b", IXIT.SoftServ, claim=REVIEW)
        self.make("5.5-4-1c", IXIT.SoftServ, claim=REVIEW)
        self.make("5.5-4-1d", IXIT.SoftServ, claim=REVIEW)
        self.make("5.5-5-1a", IXIT.SoftServ, reference="5.5-4-1")
        self.make("5.5-6-1a", IXIT.SecParam, reference="5.5-1-1")
        self.make("5.5-7-1a", IXIT.SecParam, reference="5.5-1-1")
        self.make("5.5-8-1a", IXIT.SecMgmt, claim=REVIEW)
        self.make("5.5-8-1b", IXIT.Conf, claim=REVIEW)
        self.make("5.6-1-1a", IXIT.Intf, claim=REVIEW)
        self.make("5.6-2-1a", IXIT.Intf, claim=REVIEW)
        self.make("5.6-2-1b", IXIT.Intf, claim=REVIEW)
        self.make("5.6-3-1a", IXIT.Intf, claim=REVIEW)
        self.make("5.6-3-1b", IXIT.Intf, claim=REVIEW)
        self.make("5.6-3-1c", IXIT.Intf, claim=REVIEW)
        self.make("5.6-4-1a", IXIT.Intf, claim=REVIEW)
        self.make("5.6-4-1b", IXIT.Intf, claim=REVIEW)
        self.make("5.6-4-1c", IXIT.Intf, claim=REVIEW)
        self.make("5.6-5-1a", IXIT.SoftServ, claim=REVIEW)
        self.make("5.6-6-1a", IXIT.CodeMin, claim=REVIEW)
        self.make("5.6-7-1a", IXIT.PrivlCtrl, claim=REVIEW)
        self.make("5.6-8-1a", IXIT.AccCtrl, claim=REVIEW)
        self.make("5.6-8-1b", IXIT.AccCtrl, claim=REVIEW)
        self.make("5.6-9-1a", IXIT.SecDev, claim=REVIEW)
        self.make("5.6-9-1b", IXIT.Conf, claim=REVIEW)
        self.make("5.7-1-1a", IXIT.SecBoot, claim=REVIEW)
        self.make("5.7-1-1b", IXIT.SecBoot, claim=REVIEW)
        self.make("5.7-2-1a", IXIT.SecBoot, claim=REVIEW)
        self.make("5.7-2-1b", IXIT.SecBoot, claim=REVIEW)
        self.make("5.8-1-1a", IXIT.PersData, reference="5.5-1-1")
        self.make("5.8-2-1a", IXIT.PersData, reference="5.5-1-1")
        self.make("5.9-1-1a", IXIT.ResMech, claim=REVIEW)
        self.make("5.9-1-1b", IXIT.ResMech, claim=REVIEW)
        self.make("5.9-2-1a", IXIT.ResMech, reference="5.9-1-1")
        self.make("5.9-2-1b", IXIT.ResMech, claim=REVIEW)
        self.make("5.9-2-1c", IXIT.ResMech, claim=REVIEW)
        self.make("5.9-3-1a", IXIT.ComMech, claim=REVIEW)
        self.make("5.9-3-1b", IXIT.ComMech, claim=REVIEW)
        self.make("5.10-1-1a", IXIT.TelData, claim=REVIEW)
        self.make("5.10-1-1b", IXIT.TelData, claim=REVIEW)
        self.make("5.11-1-1a", IXIT.DelFunc, claim=REVIEW)
        self.make("5.11-1-1b", IXIT.DelFunc, claim=REVIEW)
        self.make("5.11-1-1c", IXIT.DelFunc, claim=REVIEW)
        self.make("5.11-2-1a", IXIT.DelFunc, claim=REVIEW)
        self.make("5.11-2-1b", IXIT.PersData, claim=REVIEW)
        self.make("5.12-1-1a", IXIT.UserDec, claim=REVIEW)
        self.make("5.12-1-1b", IXIT.UserDec, claim=REVIEW)
        self.make("5.13-1-1a", IXIT.InpVal, claim=REVIEW)
        self.make("5.13-1-1b", IXIT.InpVal, claim=REVIEW)
        self.make("6-1-1a", IXIT.UserInfo, claim=REVIEW)
        self.make("6-2-1a", IXIT.PersData, claim=REVIEW)
        self.make("6-3-1a", IXIT.PersData, claim=REVIEW)
        self.make("6-4-1a", IXIT.PersData, claim=REVIEW)
        self.make("6-5-1a", IXIT.UserInfo, claim=REVIEW)

        # sort em
        def req_sort_key(s):
            parts = re.split(r'(\d+)', s[0])
            parts = [int(part) if part.isdigit() else part for part in parts]
            return parts

        new_r: Dict[str, Requirement] = dict(sorted(self.requirement_map.items(), key=req_sort_key))
        self.requirement_map = new_r

    def make(self, identifier: str, ixit: IXIT_Section,
             select: Optional[RequirementSelector] = None,  claim=RequirementClaim(),
             reference="") -> Requirement:
        """Make a requirement"""
        assert identifier not in self.requirement_map, f"Double {identifier}"
        assert isinstance(select, RequirementSelector) or select is None, f"Bad selector for {identifier}"
        assert isinstance(claim, RequirementClaim), f"Bad claim for {identifier}"
        # if claim == UI:
        #     ixit = IXIT.UserIntf  # NOTE: Forcing all UI claims into same target
        props = {}
        if reference:
            claim = CROSS_REFERENCE
            self.references[identifier] = reference

        if claim in {REVIEW, CROSS_REFERENCE, UI, PHYSICAL_MANIPULATION} or isinstance(claim, ContentClaim):
            # these are not added to the requirements
            priority = 0
            props[Properties.REVIEW] = True
        else:
            priority = 1
        if claim.get_base_claim() == UI:
            props[Properties.UI] = True
        if claim.get_base_claim() == CONTENT:
            props[Properties.DOCUMENT_CONTENT] = True
        unit = self.test_units[identifier]
        if unit.functional:
            props[Properties.FUNCTIONAL] = True
        if select:
            selector = select
        elif ixit.location:
            selector = ixit.location
        else:
            assert False, f"No selector for {identifier}"
        r = Requirement((self.specification_id, identifier), unit.purpose, selector, claim)
        r.priority = priority
        r.properties.update(props)
        i_split = identifier.split("-")
        sid = i_split[0]
        r.section_name = f"{sid} {self.section_names[sid]}"
        r.target_name = ixit.name
        self._add(identifier, r)
        return r

    def create_aliases(self, selected: Iterable[Tuple[Requirement, Entity, AbstractClaim]]) \
            -> Dict[Tuple[Requirement, Entity, AbstractClaim], str]:
        """ Create aliases by test targets"""
        bases: Dict[str, Set[Entity]] = {}
        for req, ent, claim in selected:
            assert req.target_name, f"Requirement {req.identifier_string()} has no target"
            bases.setdefault(req.target_name, set()).add(ent)
        aliases: Dict[str, Dict[Entity, str]] = {}
        for base, es in bases.items():
            b_d = aliases[base] = {}
            b_names = {e.long_name(): e for e in es}
            i = 0
            for _, e in sorted(b_names.items()):
                i += 1
                b_d[e] = f"{base}-{i}"
        r = {}
        for req, ent, claim in selected:
            b_d = aliases[req.target_name]
            r[req, ent, claim] = b_d[ent]
        return r

    def is_unit_specified(self, unit: 'TestUnit'):
        """Check if the test unit is specified in the specification"""
        i = self.specification_id, unit.identifier()
        return i in self.requirement_map

    def get_entity_selector(self, system: IoTSystem) -> SelectorContext:
        included = set()
        for h in system.get_hosts():
            if h.host_type not in {HostType.DEVICE}:
                continue  # focus is the devices
            included.add(h)
            included.update(h.children)
            for c in h.connections:
                # all services/hosts referenced by hosts, included too
                included.add(c)
                for e in (c.source, c.target):
                    included.add(e)
                    included.add(e.get_parent_host())

        class Selector(SpecificationSelectorContext):
            """The returned selector"""
            def include_host(self, entity: Host) -> bool:
                return entity in included and super().include_host(entity)

            def include_service(self, entity: Service) -> bool:
                return entity in included and super().include_service(entity)

            def include_connection(self, entity: Connection) -> bool:
                return entity in included and super().include_connection(entity)

        return Selector()

    def get_finnish_label_tests(self) -> Specification:
        """Get subset of tests covering requirements used in the Finnish Cybersecurity label"""
        subset = {
            "5.3-13",
            "5.12-2",
            "5.1-1",
            "5.3-2", "5.3-3", "5.3-8", "5.3-11", "5.2-1", "5.2-3",
            "6.1",
            "5.4-1", "5.5-1", "5.5-8",
            "5.5-5", "5.6-1", "5.6-7", "5.13-1",
            "5.12-1"
        }
        sub_q = {}
        for i, r in self.requirement_map.items():
            m_i, _, _ = i.rpartition("-")
            if m_i in subset:
                sub_q[i] = r
        return EtsiTs103701("etsi_ts_103_701_fin", "Fin Cybersecurity Label", sub_q)


@dataclass
class TestUnit:
    """ETSI TS 103 701 test unit"""
    case: 'TestCase'
    letter: str
    purpose: str
    functional: bool = False  # otherwise conceptual

    def identifier(self) -> str:
        """Get the identifier"""
        return f"{self.case.identifier}{self.letter}"

    def __repr__(self):
        return f"{self.letter}) {self.purpose}"


@dataclass
class TestCase:
    """ETSI TS 103 701 test case"""
    identifier: str
    purpose: str = ""
    verdict_assignment: str = ""
    units: List[TestUnit] = dataclasses.field(default_factory=list)
    conceptual: bool = False
    functional: bool = False

    def f_c_str(self) -> str:
        """Get functional/conceptual string"""
        if self.conceptual and self.functional:
            return "c/f"
        if self.conceptual:
            return "c"
        if self.functional:
            return "f"
        return ""

    def __repr__(self):
        ts = []
        if self.conceptual:
            ts.append("conceptual")
        if self.functional:
            ts.append("functional")
        # us = [f"\n  {u}" for u in self.units]
        return f"Test case {self.identifier} {self.purpose} ({'/'.join(ts)})"


def read_text_data(path: pathlib.Path = None) -> List[TestCase]:
    """Read data from text file"""
    if path is None:
        source_dir = pathlib.Path(__file__).resolve().parent
        path = source_dir / "data" / "etsi_ts_103_701.txt"
    with path.open(encoding="utf-8") as f:
        lines = f.readlines()

    tc_line = re.compile(r"Test case ([-0-9.]*)(.*)")
    tu_line = re.compile(r"([a-z])\)(.*)")
    verdict_line = re.compile("Assignment of verdict.*")

    cases = []
    tc = None
    tu = None
    for line in lines:
        line = line.strip()
        m = tc_line.fullmatch(line)
        if m:
            if tc:
                assert tc.units, f"No test units for {tc}"
                assert tc.verdict_assignment, f"No verdict assignment for {tc}"
            tc = TestCase(m.group(1))
            tu = None
            tail = m.group(2)
            tc.conceptual = "conceptual" in tail
            tc.functional = "functional" in tail
            cases.append(tc)
            continue
        m = tu_line.fullmatch(line)
        if m:
            assert not tc.verdict_assignment, f"Test unit after verdict assignment for {tc}"
            tu = TestUnit(tc, m.group(1), m.group(2).strip())
            if tc.conceptual and tc.functional:
                # both, manual intervention
                assert tc.identifier == "5.3-10-1"
                tu.functional = tu.letter == 'c'
            else:
                tu.functional = tc.functional
            tc.units.append(tu)
            continue
        va = verdict_line.fullmatch(line)
        if va:
            assert not tc.verdict_assignment
            tc.verdict_assignment = line
            continue
        if tc and tc.verdict_assignment:
            tc.verdict_assignment += f"\n{line}"
            continue
        if tu:
            tu.purpose += f"\n{line}"
        elif tu:
            if not tu.purpose:
                raise ValueError(f"No purpose for {tc.identifier} {tu}")
            tu = None
    return cases


def verify_ixit_data(specification: EtsiTs103701, path=pathlib.Path("etsi/ixit_test_targets.txt")):
    """Read IXIT data from text file, as verification"""
    with path.open(encoding="utf-8") as f:
        lines = f.readlines()

    rs: Dict[str, Set[Requirement]] = {}
    for r in specification.requirement_map.values():
        r_parts = r.identifier[1].split("-")
        rid = f"{r_parts[0]}-{r_parts[1]}"
        rs.setdefault(rid, set()).add(r)

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sid, _, name_s = line.partition(" ")
        names1 = set(n.partition("-")[2].strip() for n in name_s.split(",") if n)
        names2 = set(r.selector.get_name() for r in rs[sid])
        names2.discard(IXIT.Generic.name)
        if names1 != names2:
            print(f"MISMATCH {sid}")
            print("  Spec: " + ", ".join(sorted(names1)))
            print("  Code: " + ", ".join(sorted(names2)))




# ETSI TS 103 701 test specification
ETSI_TS_103_701 = EtsiTs103701("etsi_ts_103_701", "ETSI TS 103 701 Security perimeter")
# ...and subset with tests from Finnish Cybersecurity label
ETSI_TS_103_701_FIN = ETSI_TS_103_701.get_finnish_label_tests()


def main_print():
    """Print the specification data for debugging"""
    cl = read_text_data()
    try:
        width = os.get_terminal_size(0).columns
    except OSError:
        width = 80
    ul = []
    left = set(ETSI_TS_103_701.requirement_map.keys())
    print("== Requirements ==")
    for c in cl:
        print(f"{c}")
        for u in c.units:
            req = ETSI_TS_103_701.requirement_map.get(u.identifier())
            left.remove(u.identifier())
            m = "[X]" if req.claim != REVIEW else "[ ]"
            us = "\n       ".join(textwrap.wrap(f"{u}", width=width - 10))
            print(f"{m} {us}")

    print("== IXIT test targets ==")
    for c in cl:
        print(f"{c}")
        cfs = c.f_c_str()
        for u in c.units:
            req = ETSI_TS_103_701.requirement_map.get(u.identifier())
            txt = u.purpose.replace("\n", " ")
            print(f"{req.identifier_string(tail_only=True):<9}\t{cfs}\t{req.selector.get_name()}\t{txt}")

    print(f"Test cases: {len(cl)}")
    print(f" conceptual: {len([c for c in cl if c.conceptual])}")
    print(f" functional: {len([c for c in cl if c.functional])}")
    assert not left

    cu_c, fu_c, = 0, 0
    for c in cl:
        for u in c.units:
            if u.functional:
                fu_c += 1
            else:
                cu_c += 1
            req = ETSI_TS_103_701.requirement_map.get(u.identifier())
            ul.append(u)
    print(f"Test units: {len(ul)}")
    print(f" conceptual: {cu_c}")
    print(f" functional: {fu_c}")

    for p in (-1, 0, 1):
        c, fu_c, cu_c = 0, 0, 0
        for req in [r for r in ETSI_TS_103_701.requirement_map.values() if r.priority == p]:
            c += 1
            u = ETSI_TS_103_701.test_units[req.identifier[1]]
            if u.functional:
                fu_c += 1
            else:
                cu_c += 1
        print(f"Test units priority {p:>2}: {c} con={cu_c} fun={fu_c}")

    if pathlib.Path("etsi/ixit_test_targets.txt").exists():
        print("== IXIT verification ==")
        verify_ixit_data(ETSI_TS_103_701)

if __name__ == "__main__":
    main_print()
