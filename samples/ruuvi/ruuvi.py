# Ruuvi Gateway & Tags DSL made for research purposes
# Rauli Kaksonen, 2024
# The product is by Ruuvi, Ltd.

# pylint: disable=pointless-statement

from toolsaf.main import Builder, ARP, ICMP, EAPOL, HTTP, BLEAdvertisement, TLS, SSH, DHCP, NTP, DNS

system = Builder.new("Ruuvi Gateway & Tags")

gateway = system.device("Ruuvi Gateway").serve(EAPOL, DHCP, ARP, ICMP, DNS(captive=True))
setup_http = gateway / HTTP(auth=True)

tags = system.device("Ruuvi Tags")
ble_ad = system.broadcast(BLEAdvertisement(event_type=0x03))
tags >> ble_ad
gateway << ble_ad

user = system.browser()
user >> setup_http

mobile = system.mobile("Ruuvi app")
mobile << ble_ad

HTTP_rd = HTTP().redirect()
web_1 = system.backend("Home & Webshop").serve(SSH, TLS(auth=True)).dns("ruuvi.com")
web_2 = system.backend("Data UI").serve(SSH, HTTP, NTP, TLS(auth=True)).dns("station.ruuvi.com")
web_3 = system.backend("Analytics").serve(HTTP_rd, TLS).dns("gtm.ruuvi.com")
user >> web_1 / TLS
user >> web_2 / TLS
user >> web_3 / TLS

backend_1 = system.backend("Data backend").serve(TLS(auth=True)).dns("network.ruuvi.com")
backend_2 = system.backend("Code repository").serve(HTTP_rd, TLS).dns("github.com")
gateway >> backend_1 / TLS
gateway >> backend_2 / TLS
mobile >> backend_1 / TLS
mobile >> backend_2 / TLS

any_host = system.any("Service")
gateway >> any_host / DHCP / DNS / NTP / ICMP
gateway / ICMP

tags.set_property("default", "sensors")  # ETSI TS 103 701 requires this info

fw_esp32 = gateway.software("ESP32 Firmware").updates_from(backend_2)
fw_nRF52811 = gateway.software("nRF52811 Firmware").updates_from(backend_2)

system.online_resource("privacy-policy", url="https://ruuvi.com/privacy/",
                       keywords=["privacy policy"]
)
system.online_resource("security-policy", url="https://ruuvi.com/terms/vulnerability-policy/",
                       keywords=["security@ruuvi.com"]
)

# sensitive data
user_email = system.data(["User e-mail"])
measurements = system.data(["Measurements"])
billing_info = system.data(["Billing info"])

# Mobile application
# https://play.google.com/store/apps/details?id=com.ruuvi.station

# More DNS names (why?)
backend_2.dns("api.github.com").dns("objects.githubusercontent.com")
# Gateway NTP servers
gateway.ignore_name_requests("time.google.com", "time.nist.gov", "pool.ntp.org", "ntp1.glb.nist.gov")

# Cookies
cookies = user.cookies()
cookies.set({
    "crisp-client/*": (".ruuvi.com", "/", "Crisp chat session cookie"),
    "_fbp": (".ruuvi.com", "/", "Facebook?"),
    "FPAU": (".ruuvi.com", "/", "Google analytics"),
    "FPID": (".ruuvi.com", "/", "Google analytics"),
    "FPLC": (".ruuvi.com", "/", "Google analytics?"),
    "_ga": (".ruuvi.com", "/", "Google analytics"),
    "_ga_*": (".ruuvi.com", "/", "Google analytics"),
    "_gcl_au": (".ruuvi.com", "/", "Google analytics"),
    "station_status": (".ruuvi.com", "/", "FIXME"),
    "station_user": (".ruuvi.com", "/", "FIXME"),
    "_tt_enable_cookie": (".ruuvi.com", "/", "FIXME"),
    "_ttp": (".ruuvi.com", "/", "FIXME"),
})

# Concrete addresses
system.network().mask("192.168.0.0/16")
system.network().mask("10.10.0.0/24")
gateway.hw("30:c6:f7:52:db:5c")
tags.hw("fd:5b:e3:39:f7:24")
mobile.hw("c2:77:15:ab:b5:b0")

# Infrastructure Raspberry can do whatever
infra = system.infra().hw("dc:a6:32:28:34:e3")

if __name__ == "__main__":
    system.run()
