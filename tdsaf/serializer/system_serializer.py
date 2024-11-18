"""System serializer"""

from typing import Optional
from tdsaf.core.components import Software
from tdsaf.core.model import Addressable, Connection, Host, IoTSystem, NetworkNode, NodeComponent, Service
from tdsaf.serializer.serializer import AbstractSerializer, SerializerContext
from tdsaf.visualizer import Visualizer


class SystemSerializer(AbstractSerializer):
    """IoT system serializer"""
    def __init__(self, miniature=False, visualizer: Optional[Visualizer] = None):
        super().__init__()
        self.visualizer = visualizer
        self.miniature = miniature  # keep unit tests minimal

        with self.map_class(NetworkNode) as m:
            m.default("name")
            if not self.miniature:
                m.writer("long_name", lambda c: c.body.long_name())
            m.register(self.network_node)

        with self.map_class(Addressable).derive(NetworkNode) as m:
            if not self.miniature:
                m.writer("tag", lambda c: str(c.body.get_tag()))

        with self.map_class(Host, "host").derive(Addressable) as m:
            m.new(lambda c: Host(c.parent, c["name"]))
            if self.visualizer:
                # write xy-coordinates
                m.writer("xy", lambda c: self.visualizer.place(c.body))
                m.writer("image", lambda c: self.visualizer.images.get(c.body))

        with self.map_class(Service, "service").derive(Addressable) as m:
            m.new(lambda c: Service(c["name"], c.parent))

        with self.map_class(NodeComponent, "component") as m:
            m.abstract = True
            m.default("name")
            if not self.miniature:
                m.writer("long_name", lambda c: c.body.long_name())

        def connection_name(connection: Connection) -> Optional[str]:
            name = connection.target.name
            # s = connection.source
            # if isinstance(s, Service):
            #     name = f"{s.name}-{name}"  # looks bad on ARP and DHCP
            return name

        with self.map_class(Connection, "connection") as m:
            m.new(lambda c: Connection(c.get_referenced("source"), c.get_referenced("target")))
            if not self.miniature:
                m.writer("name", lambda c: connection_name(c.body))
                m.writer("long_name", lambda c: c.body.long_name())
            m.reference("source", "target")

        with self.map_class(Software, "sw").derive(NodeComponent) as m:
            m.new(lambda c: Software(c.parent, c["name"]))

        self.map_class(IoTSystem, "system").derive(NetworkNode)


    # pylint: disable=missing-function-docstring

    def network_node(self, new: NetworkNode) -> SerializerContext:
        ctx = SerializerContext(self.serializer_state, new)
        ctx.list(new.children, {Host, Service})
        ctx.list(new.components, {Software})
        return ctx

    def iot_system(self, new: IoTSystem) -> SerializerContext:
        ctx = self.network_node(new)
        cs = new.get_connections()
        ctx.list(cs, {Connection})  # reading not supported
        return ctx
