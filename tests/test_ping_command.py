from tcsfw.ping_command import PingCommand


def test_ping():
    r = PingCommand.parse_ping_line("PING 192.168.68.2 (192.168.68.2) 56(84) bytes of data.")
    assert r is None

    r = PingCommand.parse_ping_line("64 bytes from 192.168.68.1: icmp_seq=1 ttl=64 time=21.2 ms")
    assert r == (True, "192.168.68.1")

    r = PingCommand.parse_ping_line(
        "64 bytes from bud02s21-in-f163.1e100.net (216.58.209.163): icmp_seq=1 ttl=56 time=22.3 ms")
    assert r == (True, "216.58.209.163")


    r = PingCommand.parse_ping_line(
        "From _gateway (fe80::c206:c3ff:feee:780e) icmp_seq=1 Destination unreachable: No route")
    assert r == (False, 'fe80::c206:c3ff:feee:780e')


