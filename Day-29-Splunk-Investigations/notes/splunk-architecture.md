# Splunk Architecture

1. Forwarder: collects and forwards machine data.
2. Indexer: parses, indexes and stores events.
3. Search Head: provides the search interface.
4. Deployment Server: manages forwarder configurations.
5. Cluster Manager: coordinates indexer clusters.
6. License Manager: manages licensing and ingestion compliance.

## Event terminology

- Index: logical data store.
- Sourcetype: event format.
- Source: input source.
- Host: originating host.
- _time: event timestamp.
- _indextime: indexing timestamp.
