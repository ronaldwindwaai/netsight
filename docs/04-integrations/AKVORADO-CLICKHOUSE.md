# Akvorado + ClickHouse Integration

Purpose: NetFlow/IPFIX/sFlow traffic intelligence.

Netsight queries aggregated flow views rather than copying all flow records into PostgreSQL.

Required dimensions where available:
- time;
- source/destination;
- bytes/packets;
- ports/protocol;
- interfaces;
- ASN/country;
- application/domain enrichment where source permits;
- VLAN/site mapping.

Protect ClickHouse with a read-only query identity and query budgets/timeouts.
