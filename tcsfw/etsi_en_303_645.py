from typing import Optional, List, Union

from tcsfw.claim import Claim
from tcsfw.claim_set import Claims, UpdateClaim
from tcsfw.model import HostType
from tcsfw.requirement import Specification


def requirement(text: str, parent: Optional[str] = None,
                extends: Union[Claim, List[Claim]] = None):
    return text, parent, [extends] if isinstance(extends, Claim) else (extends or [])


# ETSI EN 303 645 V2.1.1 (2020-06)
# The present document specifies high-level security and data protection provisions for consumer IoT devices that are
# connected to network infrastructure (such as the Internet or home network) and their interactions with associated
# services. The associated services are out of scope [HOX].

# "associated services": digital services that, together with the device, are part of the overall consumer IoT product and that
# are typically required to provide the product's intended functionality
# EXAMPLE 1: Associated services can include mobile applications, cloud computing/storage and third party
# Application Programming Interfaces (APIs).

# Concepts:
# IoT device
DEVICE = (Claims.HOST.local() - Claims.host_type(HostType.BROWSER, HostType.MOBILE)).name("IoT-device")
# Authenticated device
AUTH_DEVICE = DEVICE.authenticated()
# Network service in a device
DEV_SERVICE = DEVICE.service()
# Authenticated service in a device
AUTH_DEV_SERVICE = AUTH_DEVICE.service()
# Device software
SOFTWARE = DEVICE / Claims.SOFTWARE
# Secret in device
SECRET = DEVICE / Claims.SECRET
# Connection
CONNECTION = Claims.CONNECTION
# System-level
SYSTEM = Claims.SYSTEM
# Vendor organization
VENDOR = Claims.SYSTEM


ETSI_EN_303_645 = Specification("etsi-en-303-645", "ETSI EN 303 645", {
    "5.1": requirement(
        "No universal default password"),
    "5.1-1": requirement(  # in FIN cybersecurity label
        "Where passwords are used and in any state other than the factory default, all"
        " consumer IoT device passwords shall be unique per device or defined by the user.", "5.1",
        AUTH_DEVICE),
    "5.1-2": requirement(
        "Where pre-installed unique per device passwords are used, these shall be"
        " generated with a mechanism that reduces the risk of automated attacks against a"
        " class or type of device.", "5.1",
        AUTH_DEVICE),
    "5.1-3": requirement(
        "Authentication mechanisms used to authenticate users against a device shall use"
        " best practice cryptography, appropriate to the properties of the technology,"
        " risk and usage.", "5.1",
        AUTH_DEV_SERVICE),
    "5.1-4": requirement(
        "Where a user can authenticate against a device, the device shall provide to the"
        " user or an administrator a simple mechanism to change the authentication value"
        " used.", "5.1",
        AUTH_DEVICE),
    "5.1-5": requirement(
        "When the device is not a constrained device, it shall have a mechanism available"
        " which makes bruteforce attacks on authentication mechanisms via network"
        " interfaces impracticable.", "5.1",
        AUTH_DEV_SERVICE),
    "5.2": requirement(
        "Implement a means to manage reports of vulnerabilities"),
    "5.2-1": requirement(  # in FIN cybersecurity label
        "The manufacturer shall make a vulnerability disclosure policy publicly"
        " available.", "5.2", VENDOR),
    "5.2-2": requirement(
        "Disclosed vulnerabilities should be acted on in a timely manner.", "5.2", VENDOR),
    "5.2-3": requirement(  # in FIN cybersecurity label
        "Manufacturers should continually monitor for, identify and rectify security"
        " vulnerabilities within products and services they sell, produce, have produced"
        " and services they operate during the defined support period.", "5.2", VENDOR),
    "5.3": requirement(
        "Keep software updated"),
    "5.3-1": requirement(
        "All software components in consumer IoT devices should be securely updateable.", "5.3", SOFTWARE),
    "5.3-2": requirement(  # in FIN cybersecurity label
        "When the device is not a constrained device, it shall have an update mechanism"
        " for the secure installation of updates.", "5.3",
        DEVICE.expect(UpdateClaim())),
    "5.3-3": requirement(  # in FIN cybersecurity label
        "An update shall be simple for the user to apply.", "5.3",
        DEVICE / UpdateClaim()),
    "5.3-4": requirement(
        "Automatic mechanisms should be used for software updates.", "5.3", SOFTWARE),
    "5.3-5": requirement(
        "The device should check after initialization, and then periodically, whether"
        " security updates are available", "5.3", SOFTWARE),
    "5.3-6": requirement(
        "If the device supports automatic updates and/or update notifications, these"
        " should be enabled in the initialized state and configurable so that the user can"
        " enable, disable, or postpone installation of security updates and/or update"
        " notifications.", "5.3", SOFTWARE),
    "5.3-7": requirement(
        "The device shall use best practice cryptography to facilitate secure update"
        " mechanisms.", "5.3", SOFTWARE),
    "5.3-8": requirement(  # in FIN cybersecurity label
        "Security updates shall be timely.", "5.3", VENDOR),
    "5.3-9": requirement(
        "The device should verify the authenticity and integrity of software updates.", "5.3", SOFTWARE),
    "5.3-10": requirement(
        "Where updates are delivered over a network interface, the device shall verify"
        " the authenticity and integrity of each update via a trust relationship.", "5.3", SOFTWARE),
    "5.3-11": requirement(  # in FIN cybersecurity label
        "The manufacturer should inform the user in a recognizable and apparent manner"
        " that a security update is required together with information on the risks"
        " mitigated by that update.", "5.3", VENDOR),
    "5.3-12": requirement(
        "The device should notify the user when the application of a software update will"
        " disrupt the basic functioning of the device.", "5.3", SOFTWARE),
    "5.3-13": requirement(  # in FIN cybersecurity label
        "The manufacturer shall publish, in an accessible way that is clear and"
        " transparent to the user, the defined support period.", "5.3", VENDOR),
    "5.3-14": requirement(
        "For constrained devices that cannot have their software updated, the rationale"
        " for the absence of software updates, the period and method of hardware"
        " replacement support and a defined support period should be published by the"
        " manufacturer in an accessible way that is clear and transparent to the user.", "5.3", SOFTWARE),
    "5.3-15": requirement(
        "For constrained devices that cannot have their software updated, the product"
        " should be isolable and the hardware replaceable.", "5.3", DEVICE),
    "5.3-16": requirement(
        "The model designation of the consumer IoT device shall be clearly recognizable,"
        " either by labelling on the device or via a physical interface.", "5.3", DEVICE),
    "5.4": requirement(
        "Securely store sensitive security parameters"),
    "5.4-1": requirement(  # in FIN cybersecurity label
        "Sensitive security parameters in persistent storage shall be stored securely by"
        " the device.", "5.4", SECRET),
    "5.4-2": requirement(
        "Where a hard-coded unique per device identity is used in a device for security"
        " purposes, it shall be implemented in such a way that it resists tampering by"
        " means such as physical, electrical or software.", "5.4", DEVICE),
    "5.4-3": requirement(
        "Hard-coded critical security parameters in device software source code shall not"
        " be used", "5.4", SOFTWARE),
    "5.4-4": requirement(
        "Any critical security parameters used for integrity and authenticity checks of"
        " software updates and for protection of communication with associated services in"
        " device software shall be unique per device and shall be produced with a"
        " mechanism that reduces the risk of automated attacks against classes of devices.", "5.4", DEVICE),
    "5.5": requirement(
        "Communicate securely"),
    "5.5-1": requirement(  # in FIN cybersecurity label
        "The consumer IoT device shall use best practice cryptography to communicate"
        " securely.", "5.5", Claims.CONNECTION.expect(Claims.CRYPTO_CHECKED)),
    "5.5-2": requirement(
        "The consumer IoT device should use reviewed or evaluated implementations to"
        " deliver network and security functionalities, particularly in the field of"
        " cryptography.", "5.5", SOFTWARE),
    "5.5-3": requirement(
        "Cryptographic algorithms and primitives should be updateable.", "5.5", SOFTWARE),
    "5.5-4": requirement(
        "Access to device functionality via a network interface in the initialized state"
        " should only be possible after authentication on that interface.", "5.5", DEV_SERVICE),
    "5.5-5": requirement(  # in FIN cybersecurity label
        "Device functionality that allows security-relevant changes in configuration via"
        " a network interface shall only be accessible after authentication. The exception"
        " is for network service protocols that are relied upon by the device and where"
        " the manufacturer cannot guarantee what configuration will be required for the"
        " device to operate.", "5.5", DEV_SERVICE.expect(DEVICE.authenticated())),
    "5.5-6": requirement(
        "Critical security parameters should be encrypted in transit, with such"
        " encryption appropriate to the properties of the technology, risk and usage.", "5.5",
        [Claims.CONNECTION.expect(Claims.CRYPTO_CHECKED)]),
    "5.5-7": requirement(
        "The consumer IoT device shall protect the confidentiality of critical security"
        " parameters that are communicated via remotely accessible network interfaces.", "5.5",
        [DEV_SERVICE]),
    "5.5-8": requirement(  # in FIN cybersecurity label
        "The manufacturer shall follow secure management processes for critical security"
        " parameters that relate to the device.", "5.5", SECRET),
    "5.6": requirement(
        "Minimize exposed attack surface"),
    "5.6-1": requirement(  # in FIN cybersecurity label
        "All unused network and logical interfaces shall be disabled.", "5.6",
        DEVICE.expect(Claims.NO_UNEXPECTED_SERVICES)),
    "5.6-2": requirement(
        "In the initialized state, the network interfaces of the device shall minimize"
        " the unauthenticated disclosure of security-relevant information.", "5.6", DEV_SERVICE),
    "5.6-3": requirement(
        "Device hardware should not unnecessarily expose physical interfaces to attack.", "5.6", DEVICE),
    "5.6-4": requirement(
        "Where a debug interface is physically accessible, it shall be disabled in"
        " software", "5.6", DEVICE),
    "5.6-5": requirement(
        "The manufacturer should only enable software services that are used or required"
        " for the intended use or operation of the device.", "5.6", DEV_SERVICE),
    "5.6-6": requirement(
        "Code should be minimized to the functionality necessary for the service/device"
        " to operate.", "5.6", SOFTWARE),
    "5.6-7": requirement(  # in FIN cybersecurity label
        "Software should run with least necessary privileges, taking account of both"
        " security and functionality", "5.6", SOFTWARE),
    "5.6-8": requirement(
        "The device should include a hardware-level access control mechanism for memory.", "5.6", DEVICE),
    "5.6-9": requirement(
        "The manufacturer should follow secure development processes for software"
        " deployed on the device.", "5.6", SOFTWARE),
    "5.7": requirement(
        "Ensure software integrity"),
    "5.7-1": requirement(
        "The consumer IoT device should verify its software using secure boot mechanisms", "5.7", SOFTWARE),
    "5.7-2": requirement(
        "If an unauthorized change is detected to the software, the device should alert"
        " the user and/or administrator to the issue and should not connect to wider"
        " networks than those necessary to perform the alerting function.", "5.7", SOFTWARE),
    "5.8": requirement(
        "Ensure that personal data is secure"),
    "5.8-1": requirement(
        "The confidentiality of personal data transiting between a device and a service,"
        " especially associated services, should be protected, with best practice"
        " cryptography.", "5.8", [Claims.CONNECTION.expect(Claims.CRYPTO_CHECKED)]),
    "5.8-2": requirement(
        "The confidentiality of sensitive personal data communicated between the device"
        " and associated services shall be protected, with cryptography appropriate to the"
        " properties of the technology and usage.", "5.8", [Claims.CONNECTION.expect(Claims.CRYPTO_CHECKED)]),
    "5.8-3": requirement(
        "All external sensing capabilities of the device shall be documented in an"
        " accessible way that is clear and transparent for the user.", "5.8", DEVICE),
    "5.9": requirement(
        "Make systems resilient to outages"),
    "5.9-1": requirement(
        "Resilience should be built in to consumer IoT devices and services, taking into"
        " account the possibility of outages of data networks and power.", "5.9", DEVICE),
    "5.9-2": requirement(
        "Consumer IoT devices should remain operating and locally functional in the case"
        " of a loss of network access and should recover cleanly in the case of"
        " restoration of a loss of power.", "5.9", DEVICE),
    "5.9-3": requirement(
        "The consumer IoT device should connect to networks in an expected, operational"
        " and stable state and in an orderly fashion, taking the capability of the"
        " infrastructure into consideration", "5.9", DEVICE),
    "5.10": requirement(
        "Examine system telemetry data"),
    "5.10-1": requirement(
        "If telemetry data is collected from consumer IoT devices and services, such as"
        " usage and measurement data, it should be examined for security anomalies.", "5.10", VENDOR),
    "5.11": requirement(
        "Make it easy for users to delete user data"),
    "5.11-1": requirement(
        "The user shall be provided with functionality such that user data can be erased"
        " from the device in a simple manner.", "5.11", Claims.PRIVATE),
    "5.11-2": requirement(
        "The consumer should be provided with functionality on the device such that"
        " personal data can be removed from associated services in a simple manner.", "5.11", Claims.PRIVATE),
    "5.11-3": requirement(
        "Users should be given clear instructions on how to delete their personal data.", "5.11", Claims.PRIVATE),
    "5.11-4": requirement(
        "Users should be provided with clear confirmation that personal data has been"
        " deleted from services, devices and applications.", "5.11", Claims.PRIVATE),
    "5.12": requirement(
        "Make installation and maintenance of devices easy"),
    "5.12-1": requirement(  # in FIN cybersecurity label
        "Installation and maintenance of consumer IoT should involve minimal decisions by"
        " the user and should follow security best practice on usability.", "5.12", DEVICE),
    "5.12-2": requirement(  # in FIN cybersecurity label
        "The manufacturer should provide users with guidance on how to securely set up"
        " their device.", "5.12", DEVICE),
    "5.12-3": requirement(
        "The manufacturer should provide users with guidance on how to check whether"
        " their device is securely set up.", "5.12", DEVICE),
    "5.13": requirement(
        "Validate input data"),
    "5.13-1": requirement(  # in FIN cybersecurity label
        "The consumer IoT device software shall validate data input via user interfaces"
        " or transferred via Application Programming Interfaces (APIs) or between networks"
        " in services and devices.", "5.13", DEV_SERVICE),
    "6": requirement(
        "Data protection provisions for consumer IoT"),
    "6-1": requirement(  # in FIN cybersecurity label
        "The manufacturer shall provide consumers with clear and transparent information"
        " about what personal data is processed, how it is being used, by whom, and for"
        " what purposes, for each device and service. This also applies to third parties"
        " that can be involved, including advertisers.", "6", Claims.PRIVATE),
    "6-2": requirement(
        "Where personal data is processed on the basis of consumers' consent, this"
        " consent shall be obtained in a valid way.", "6", Claims.PRIVATE),
    "6-3": requirement(
        "Consumers who gave consent for the processing of their personal data shall have"
        " the capability to withdraw it at any time.", "6", Claims.PRIVATE),
    "6-4": requirement(
        "If telemetry data is collected from consumer IoT devices and services, the"
        " processing of personal data should be kept to the minimum necessary for the"
        " intended functionality.", "6", VENDOR),
    "6-5": requirement(
        "If telemetry data is collected from consumer IoT devices and services, consumers"
        " shall be provided with information on what telemetry data is collected, how it"
        " is being used, by whom, and for what purposes.", "6", VENDOR),
})
ETSI_EN_303_645.host_filter = DEVICE  # only devices included

def ixit(text: str, extends: Union[Claim, List[Claim]] = None):
    return text, None, [extends] if isinstance(extends, Claim) else (extends or [])


class EtsiTs103_701(Specification):
    def __init__(self):
        super().__init__("etsi-ts-103-701", "ETSI TS 103 701", {})
        self.short_infos = True
        self.host_filter = DEVICE  # only devices included

        self._add("1-AuthMech", "Authentication Mechanisms", DEV_SERVICE)
        self._add("2-UserInfo", "User Information", VENDOR)
        self._add("3-VulnTypes", "Relevant Vulnerabilities", SOFTWARE)
        self._add("4-Conf", "Confirmations", VENDOR)
        self._add("5-VulnMon", "Vulnerability Monitoring", VENDOR)
        self._add("6-SoftComp", "Software Components", SOFTWARE)
        self._add("7-UpdMech", "Update Mechanisms", CONNECTION)
        self._add("8-UpdProc", "Update Procedures", VENDOR)
        self._add("9-ReplSup", "Replacement Support", VENDOR)
        self._add("10-SecParam", "Security Parameters", SECRET)
        self._add("11-ComMech", "Communication Mechanisms", CONNECTION.verdict())
        self._add("12-NetSecImpl", "Network and Security Implementations", DEV_SERVICE, SOFTWARE)
        self._add("13-SoftServ", "Software Services", DEV_SERVICE, SOFTWARE)
        self._add("14-SecMgmt", "Secure Management Processes", VENDOR)
        self._add("15-Intf", "Interfaces", DEV_SERVICE)
        self._add("16-CodeMin", "Code Minimization", SOFTWARE)
        self._add("17-PrivlCtrl", "Privilege Control", SOFTWARE)
        self._add("18-AccCtrl", "Access Control", SOFTWARE)
        self._add("19-SecDev", "Secure Development Processes", VENDOR)
        self._add("20-SecBoot", "Secure Boot Mechanisms", SOFTWARE)
        self._add("21-PersData", "Personal Data", SECRET)
        self._add("22-ExtSens", "External Sensors", DEVICE)
        self._add("23-ResMech", "Resilience Mechanisms", SYSTEM)
        self._add("24-TelData", "Telemetry Data", CONNECTION)
        self._add("25-DelFunc", "Deletion Functionalities", SYSTEM)
        self._add("26-UserDec", "User Decisions", SYSTEM)
        self._add("27-UserIntf", "User Interfaces", DEVICE)
        self._add("28-ExtAPI", "External APIs", DEV_SERVICE)
        self._add("29-InpVal", "Data Input Validation", DEV_SERVICE)

    def _add(self, id_str: str, name: str, something, jee=None):
        pass # FIXME no action


ETSI_TS_103_701 = EtsiTs103_701()


FinnishCybersecurityLabel = ETSI_EN_303_645.derive("fin-cybersecurity", "FIN Cybersecurity Label",
                                                   with_requirements={
    "5.3-13",
    "5.12-2",
    "5.1-1",
    "5.3-2", "5.3-3", "5.3-8", "5.3-11", "5.2-1", "5.2-3",
    "6.1",
    "5.4-1", "5.5-1", "5.5-8",
    "5.5-5", "5.6-1", "5.6-7", "5.13-1",
    "5.12-1"
})


if __name__ == "__main__":
    spec = FinnishCybersecurityLabel
    print(f"{spec}")
