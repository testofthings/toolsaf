"""Device-backend-mobile sample security statement"""
from toolsaf.main import Builder, TLS, DHCP, DNS, Proprietary

# System root and its name
system = Builder.new(__doc__)
system.tag("test1242")

# Define IoT device(s) and gateway
device = system.device()
gateway = system.device("Gateway")

# Define backend servers(s)
backend_1 = system.backend().dns("be1.example.com")
backend_2 = system.backend().dns("be2.example.com")

# Define mobile app
app = system.mobile("App")

# Define connection(s)
device >> gateway / Proprietary("connection-protocol")  # protocol not supported by framework, yet
gateway >> backend_1 / TLS
gateway >> backend_2 / TLS
app >> backend_2 / TLS
app >> gateway / TLS(port=8886)

# Some services by environment
env = system.any()
gateway >> env / DHCP / DNS


# Run the system builder
if __name__ == '__main__':
    system.run()
