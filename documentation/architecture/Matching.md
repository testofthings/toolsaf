# Matching traffic and addresses

One of the key functionalities of Toolsaf is to read a PCAP file and check if the extracted
information matches the security statement.
This requires *matching* IP and HW addresses, multicast addresses, protocols, and ports into
system entities.

This functionality is implemented in Python modules `matcher.py` and `matcher_engine.py`.
The following describes the roles of different Python classes:

## `SystemMatcher`

Implements the `ModelInterface` so that matchers sit in the Toolsaf processing pipeline.
System matcher is called by `Inspector` to map between flows and addresses and system entities.

## `MatchingContext`

A matching context is associated with one *evidence source* which matches a result directory
and its metadata file (`00meta.json`) with cumulative definitions from possible subdirectory
metafiles.
Contexts are kept in a dictionary, so that when a capture *flow* is processed
the right context is picked according to the source of the events.
A new context is created for each new evidence source.

A context uses a `MatcherEngine` to do the matching.
However, if the flow has already been seen before, the cached `ConnectionMatch` provides a match quickly.
Context can then create new connections and endpoints, if the matching engine did not find existing ones.
It also updates connection statuses from UNEXPECTED to EXTERNAL, when that is applicable.

## `MatchingEngine`

This is the heart of the matching function.
It maintains dictionaries of related data:

* `endpoints`: Address *clues* for each addressable entity, which can be *hosts* (class `Host`) or *services* (class `Service` or its subclass).

* `addresses`: Address clues by IP and HW addresses. Addresses contain the *network* information
(ATM this is work in progress, expect the network to be `local` for all).

* `wildcard_hosts`: Address clues for hosts which match many addresses.

* `connections`: Connection clues for connections.

### `FlowMatcher`

A flow matcher matches one traffic flow (IP flow or other type of flow).
Flow matcher produces matching state (`MatchingState`) for source and target ends of a flow separately.
First, in constructor `__init__`, the matcher calculates matching weight values for all potential endpoints and connections for the flow ends (source and target).
Then, in the method `get_connection`, the matcher tries to find a matching connection with maximum weight.
The result of flow matching can be:

1. Matched connection
1. Two matching endpoints (hosts or services), but no suitable connection between them
1. One matching endpoint, either target or source
1. No matching endpoints

The connection or endpoints can also be *reverse direction* (also called *reply*), so that flow direction
is reversed.

The matching context then uses this information to return the connection or creates a new connection and endpoints,
as required to represent the flow.

### `AddressClue`

Address clue contains information for matching an address (host or service).
It has the following key fields:

* `entity`: The entity (host or service) to match
* `services`: Services for a host, keyed by protocol+port
* `endpoints`: Service's own endpoints as protocol+port
* `addresses`: All addresses of the entity, they can come from:
   - The security statement
   - A metafile
   - Learned from traffic, e.g. DNS names
* `soft_addresses`: Addresses learned from traffic, which can be overridden by new information.
* `source_for` and `target_for`: The connections this entity is a source or target for.

With this information address clue updates the matching state taking into account information from the flow.
The address clue assigns a weight for itself in the state - the larger the value, the more it looks like the flow
end matches the entity represented by this address clue.

### `ConnectionClue`

Connection clue calculates the weight for the connection.
The weight is also calculated separately for the source and target ends of the connection.
