"""Device-backend sample security statement"""
from toolsaf.main import Builder, TLS

# System root and its name
system = Builder.new(__doc__)

# Define IoT device(s)
device = system.device()

# Define backend servers(s)
backend = system.backend()

# Define connection(s)
device >> backend / TLS


# Run the system builder
if __name__ == '__main__':
    system.run()
