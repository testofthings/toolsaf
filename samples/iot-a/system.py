import tcsfw
from tcsfw.main import Builder, TLS
from tcsfw.traffic import IPFlow

system = Builder.new("IoT A")
device = system.device()
backend = system.backend().serve(TLS(auth=True))
app = system.mobile()

device >> backend / TLS
app >> backend / TLS

# Visualization
system.visualize().place(
    "D   A",
    "  B  ",
) .where({
    "D": device,
    "B": backend,
    "A": app
})

# Load some fake traffic
load = system.load()
load.traffic("Data set I").hw(device, "1:0:0:0:0:1").ip(backend, "10.10.0.2") \
    .connection(Builder.TCP("1:0:0:0:0:1", "192.168.0.1", 1100) >> ("1:0:0:0:0:2", "10.10.0.2", 443))

if __name__ == "__main__":
    system.run()
