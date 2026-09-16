# Network logs (`network` family)

`network-events.ndjson` — synthetic flows plus periodic `flow_summary` events.
Uses `source.ip` / `destination.ip` and `source.plane` / `destination.plane`.
Carries the enrichment field `network.bytes_out_10m` on `flow_summary`.
Documentation-safe identifiers only. See [`../README.md`](../README.md).
