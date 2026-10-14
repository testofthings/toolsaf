"""Removing entities and networks from the model"""

from typing import List

from toolsaf.common.address import Network
from toolsaf.common.entity import Entity
from toolsaf.core.components import Software
from toolsaf.core.model import Addressable, Connection, IoTSystem, NetworkNode, NodeComponent
from toolsaf.main import ConfigurationException


class EntityRemoval:
    """Removal of an entity or a network from the model, instantiate for each removal"""
    def __init__(self, system: IoTSystem) -> None:
        self.system = system
        self.entities: List[Entity] = []  # removed entities
        self.ignore_rules_changed = False

    def remove_entity(self, entity: Entity) -> None:
        """Remove host, service, connection, or component, e.g. software.
        Services and components of a removed host or service are removed, too.
        Fails if connections refer to them, or if a removed connection is used for updates."""
        match entity:
            case IoTSystem():
                raise ConfigurationException("Cannot remove the system")
            case Addressable():
                self._remove_node(entity)
            case Connection():
                self._remove_connection(entity)
            case NodeComponent():
                self._remove_component(entity)
            case _:
                raise ConfigurationException(f"Cannot remove {entity}")

    def remove_network(self, network: Network) -> None:
        """Remove network, fails if it is used. Networks are only referred by entities, nothing to detach"""
        if network in self.system.networks:
            raise ConfigurationException(f"Cannot remove system network {network.name}")
        for e in self.system.iterate(relevant_only=False):
            if isinstance(e, NetworkNode) and network in e.networks:
                raise ConfigurationException(f"Network {network.name} is used by {e.long_name()}")

    def _remove_node(self, entity: Addressable) -> None:
        """Remove host or service with its services and components"""
        nodes: List[Addressable] = []  # parents before children
        def collect(node: Addressable) -> None:
            nodes.append(node)
            for c in node.children:
                collect(c)
        collect(entity)
        connections = [c for c in self.system.get_connections(relevant_only=False)
                       if c.source in nodes or c.target in nodes]
        if connections:
            names = ", ".join(c.long_name() for c in connections)
            raise ConfigurationException(f"Remove first connections of {entity.long_name()}: {names}")

        for node in nodes:
            self.entities.append(node)
            self.entities.extend(node.components)
        self._remove_ignore_rules()
        for node in nodes:
            self.system.message_listeners.pop(node, None)
        entity.parent.children.remove(entity)

    def _remove_connection(self, connection: Connection) -> None:
        """Remove connection"""
        for e in self.system.iterate(relevant_only=False):
            if isinstance(e, Software) and connection in e.update_connections:
                raise ConfigurationException(
                    f"Connection {connection.long_name()} used for updates by {e.long_name()}")
        self.entities.append(connection)
        self._remove_ignore_rules()
        for h in (connection.source.get_parent_host(), connection.target.get_parent_host()):
            if connection in h.connections:
                h.connections.remove(connection)
        self.system.connections = {k: v for k, v in self.system.connections.items() if v is not connection}

    def _remove_component(self, component: NodeComponent) -> None:
        """Remove software, cookies, or other component"""
        self.entities.append(component)
        self._remove_ignore_rules()
        component.entity.components.remove(component)

    def _remove_ignore_rules(self) -> None:
        """Remove locations of removed entities from ignore rules, call before detaching the entities"""
        addresses = {e.get_system_address().get_parseable_value() for e in self.entities}
        rules = self.system.ignore_rules.rules
        for file_type, rule_list in list(rules.items()):
            for rule in [r for r in rule_list if r.at & addresses]:
                rule.at -= addresses
                if not rule.at:
                    rule_list.remove(rule)  # empty location would mean everywhere
                self.ignore_rules_changed = True
            if not rule_list:
                del rules[file_type]
