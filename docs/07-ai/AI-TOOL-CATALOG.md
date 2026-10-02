# AI Tool Catalog — MVP

Read-only:
- get_device(device_id)
- find_device(query)
- get_device_health(device_id)
- get_interfaces(device_id)
- get_topology_neighbours(device_id)
- get_path_context(source_id, destination)
- get_flow_summary(entity_id, start, end)
- get_top_destinations(entity_id, start, end)
- get_security_events(entity_id, start, end)
- get_recent_config_changes(device_id, start, end)
- get_probe_results(service_id, start, end)
- run_ping(device_id)
- run_dns_test(name)
- run_tcp_test(target, approved_port)
- run_http_probe(service_id)
- get_identity_context(entity_id)
- search_knowledge(query)

Not available directly to AI in MVP:
- disable_port
- restart_server
- change_firewall
- quarantine_endpoint
- rollback_config
- modify_IAM

AI may call `propose_action(action_type,target,reason,evidence_ids)` which creates an inert Action Request requiring policy/human approval.
