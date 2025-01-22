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

fw_esp32 = gateway.software("ESP32 Firmware").updates_from(backend_2)
fw_nRF52811 = gateway.software("nRF52811 Firmware").updates_from(backend_2)

system.online_resource("privacy-policy", url="https://ruuvi.com/privacy/",
                       keywords=["privacy policy"]
)
system.online_resource("security-policy", url="https://ruuvi.com/terms/vulnerability-policy/",
                       keywords=["security@ruuvi.com"]
)

# Mobile application
# https://play.google.com/store/apps/details?id=com.ruuvi.station

# Additional DNS names
backend_2.dns("api.github.com").dns("objects.githubusercontent.com")
# Gateway NTP servers
gateway.ignore_name_requests("time.google.com", "time.nist.gov", "pool.ntp.org", "ntp1.glb.nist.gov")

# Cookies (experimental feature, perhaps not a way forward)
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

# Network masks
system.network().mask("192.168.0.0/16")  # Assuming 192.168 local network
system.network().mask("10.10.0.0/24")    # Gateway's setup network

if __name__ == "__main__":
    system.run()
