from tcsfw.model import HostType
from tcsfw.selector import Locations
from tcsfw.main import Builder, TLS, HTTP, SSH


def make_claims(system: Builder, gateway, tags, user, mobile, backend_1, backend_2, web_1, web_2, web_3, ble_ad):
    claims = system.claims()

    # Ignore some finding(s)
    claims.ignore() \
        .key("testssl", "BREACH") \
        .at(web_1 / TLS, web_2 / TLS, backend_2 / TLS)
    claims.ignore() \
        .key("testssl", "cipher_order") \
        .at(web_1 / TLS, web_2 / TLS)
    claims.ignore() \
        .keys(("zed", "10202"), ("zed", "10098"), ("zed", "10038"), ("zed", "10020-1")) \
        .at(web_1 / TLS, web_2 / TLS)

    claims.ignore() \
        .key("ssh-audit", "del", "kex", "diffie-hellman-group14-sha1") \
        .key("ssh-audit", "del", "kex", "ecdh-sha2-nistp256") \
        .key("ssh-audit", "del", "kex", "ecdh-sha2-nistp384") \
        .key("ssh-audit", "del", "kex", "ecdh-sha2-nistp521") \
        .key("ssh-audit", "del", "key", "ecdsa-sha2-nistp256") \
        .key("ssh-audit", "del", "key", "ssh-rsa") \
        .key("ssh-audit", "del", "mac", "hmac-sha1") \
        .key("ssh-audit", "del", "mac", "hmac-sha1-etm@openssh.com") \
        .at(web_1 / SSH, web_2 / SSH)

    claims.reviewed("HTTP redirect missed by used tools, but it is there") \
        .key("check", "http-redirect").at(web_2 / HTTP)

    claims.ignore("Tag updates require manual work") \
        .software(tags).key("check", "update-mechanism")

    claims.ignore("Gateway configuration hotspot does not use SSL. This is because SSL certificates cannot be verified "
                  "while not connected to the Internet.") \
        .at(gateway / HTTP, user >> gateway / HTTP).key("check", "encryption")

    claims.ignore("Ruuvi tag data is broadcast plaintext").at(tags >> ble_ad).key("check", "encryption")

    claims.ignore("SBOM not available").software(gateway, tags, user, backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "components")
    claims.claim(
        "From Vulnerability Policy:"
        ' "To the best of our ability, we will confirm the existence of the vulnerability to you and be as transparent'
        ' as possible about what steps we are taking during the remediation process, including on issues or challenges'
        ' that may delay resolution."') \
        .software(gateway, tags, user, backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "vulnz")

    claims.ignore("Release information not available").software(user, backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "release-history")

    claims.ignore("Documents not relevant").at(gateway).key("check", "avail")  # , "replacement")

    claims.reviewed("Ruuvi Gateways use unique 64-bit passwords by default. "
                    "Default passwords can be changed by the user.") \
        .key("check", "auth").at(gateway / HTTP)

    claims.reviewed("Ruuvi Cloud uses strong random access tokens to authenticate users") \
        .key("check", "auth").at(backend_1 / TLS, web_1 / TLS, web_2 / TLS)

    claims.ignore("3rd party services do not authenticate users") \
        .key("check", "auth").at(backend_2 / TLS, web_3 / TLS)

    claims.reviewed("Ruuvi Cloud is updated directly on the backend, no user interaction is required") \
        .software(backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "update-mechanism")

    # NOTE - DEMO: Not really reviewed at all
    claims.ignore("Reviewed vulnerabilities").software(mobile).vulnerabilities(
        ("commons-beanutils", "CVE-2019-10086"),
        ("commons-beanutils", "CVE-2014-0114"),
        ("commons-collections", "CVE-2015-6420"),
        ("commons-collections", "CVE-2015-7501"),
        ("commons-collections", "CVE-2017-15708"),
        ("commons-collections", "CVE-2015-8545"),
        ("kotlin", "CVE-2019-10101"),
        ("kotlin", "CVE-2019-10103"),
        ("kotlin", "CVE-2019-10102"),
        ("okhttp", "CVE-2016-2402"),
    )

    plans = system.load()
    # ETSI TS 103 701 - PLANNING
    plans.plan_tool("conn-tls-check", "TLS conn. audit*", Locations.CONNECTION.protocol("tls"),
                    ("check", "traffic", "tls"))
    basic_func = plans.plan_tool("basic-func", "Basic function test*",
                                 Locations.SYSTEM + Locations.HOST.type_of(HostType.DEVICE),
                                 ("check", "basic-function"))
    isolate = plans.plan_tool("isolate", "Isolate network/power*", Locations.SYSTEM + Locations.HOST,
                              ("action", "isolate"))
    # auth_scan = plans.plan_tool("auth-scan", "Auth scanner*", Locations.SERVICE, ("check", "no-auth"))
    auth_grant = plans.plan_tool("auth-grant", "Auth audit*", Locations.SERVICE.authenticated(),
                                 ("check", "auth"), ("check", "auth-grant"))
    tele = plans.plan_tool("tele", "Telemetry audit*", Locations.SYSTEM, ("check", "telemetry"))
    password_crack = plans.plan_tool("password-crack", "Password cracker*", Locations.SERVICE.authenticated(),
                                     ("check", "password-cracking"))
    code = plans.plan_tool("code", "Code analysis*", Locations.SOFTWARE, ("check", "code-security"))
    modify_sw = plans.plan_tool("modify_sw", "Modify device SW*", Locations.SOFTWARE,("check", "modify-sw"))
    storage = plans.plan_tool("storage", "Secure storage analysis*", Locations.DATA.parameters(),
                              ("check", "secure-storage"))
    param_changed = plans.plan_tool("param_change", "Check that parameter updated*",
                                    Locations.DATA.parameters(),("check", "param-changed"))
    password_valid = plans.plan_tool("password-valid", "Password validator*", Locations.SERVICE.authenticated(),
                                     ("check", "password-validity"))
    fuzz = plans.plan_tool("fuzz", "Fuzzer*", Locations.SERVICE, ("check", "fuzz"))
    update_crack = plans.plan_tool("update-crack", "Update cracker*", Locations.CONNECTION + Locations.SOFTWARE,
                                   ("check", "mod-update"))

    plans.group("internals", code, storage)
    plans.group("disturbing", isolate, password_crack, fuzz, update_crack)
