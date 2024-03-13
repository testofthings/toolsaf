from tcsfw.basics import HostType
from tcsfw.selector import Select
from tcsfw.main import TLS, HTTP, SSH, SystemBuilder


def make_claims(system: SystemBuilder, gateway, tags, user, mobile, backend_1, backend_2, web_1, web_2, web_3, ble_ad):
    claims = system.claims(base_label="false-positives")

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

    claims.set_base_label("explain")  # in effect below

    claims.reviewed("HTTP redirect missed by used tools, but it is there") \
        .key("default", "http-redirect").at(web_2 / HTTP)

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
        .key("check", "vulnz") \
        .verdict_ignore()

    claims.ignore("Release information not available").software(user, backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "release-history")

    claims.ignore("Documents not relevant").at(gateway).key("check", "avail")  # , "replacement")

    claims.reviewed("Ruuvi Gateways use unique 64-bit passwords by default. "
                    "Default passwords can be changed by the user.") \
        .key("check", "auth").at(gateway / HTTP)

    claims.reviewed("Ruuvi Cloud uses strong random access tokens to authenticate users") \
        .key("check", "auth").at(backend_1 / TLS, web_1 / TLS, web_2 / TLS)

    claims.ignore("3rd party services do not authenticate users") \
        .key("check", "auth").at(backend_2 / TLS, web_3 / TLS) \
        .verdict_ignore

    claims.reviewed("Ruuvi Cloud is updated directly on the backend, no user interaction is required") \
        .software(backend_1, backend_2, web_1, web_2, web_3) \
        .key("check", "update-mechanism") \
        .verdict_ignore()

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

    # Tool planning

    group = "basic-tools", "Basic tools"
    claims.plan_tool("TLS conn. audit*", group, Select.connection().protocol("tls"),
                     ("check", "traffic", "tls"))

    group = "advanced-tools", "Advanced tools"
    claims.plan_tool("Isolate network/power*", group, Select.system() + Select.host(),
                     ("action", "isolate"))
    claims.plan_tool("Code analysis*", group, Select.software(), ("check", "code-review"))
    claims.plan_tool("Fuzzer*", group, Select.service(), ("check", "fuzz"))

    group = "custom-tools", "Custom tools"
    claims.plan_tool("Basic function test*", group,
                     Select.system() + Select.host().type_of(HostType.DEVICE),
                     ("check", "basic-function"))
    claims.plan_tool("Auth audit*", group, Select.service().authenticated(),
                     ("check", "auth", "best-practice"), ("check", "auth", "no-vulnz"), 
                     ("check", "auth", "brute-force"),
                     ("check", "auth"), ("check", "auth", "grant"))
    claims.plan_tool("Modify device SW*", group, Select.software(),("check", "modify-sw"))
    claims.plan_tool("Secure storage analysis*", group, Select.data().parameters(),
                     ("check", "secure-storage"))
    claims.plan_tool("Check that parameter updated*", group,
                     Select.data().parameters(),("check", "param-changed"))
    claims.plan_tool("Password validator*", group, Select.service().authenticated(),
                     ("check", "password-validity"))
    claims.plan_tool("Update cracker*", group, Select.connection() + Select.software(),
                     ("check", "mod-update"))
    claims.plan_tool("Telemetry audit*", group, Select.system(), ("check", "telemetry"))
