-- Seeds the "advanced platform" policies added in policies/*.yaml (ICS/OT
-- protocol exposure, cloud metadata reachability, IAM review trigger,
-- flat-network segmentation for critical hosts).

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('ics-protocol-exposed', 'Industrial control protocol reachable',
 'Modbus, S7comm, OPC-UA, or BACnet confirmed reachable and publicly exposed.',
 'critical', 'Isolate ICS/OT protocols on a dedicated, firewalled OT segment.',
 '{"target":"service","all":[{"field":"exposed_publicly","operator":"eq","value":true}],"any":[{"field":"protocol_family","operator":"eq","value":"modbus"},{"field":"protocol_family","operator":"eq","value":"s7"},{"field":"protocol_family","operator":"eq","value":"opcua"},{"field":"protocol_family","operator":"eq","value":"bacnet"}]}'),

('cloud-metadata-reachable', 'Cloud instance metadata endpoint reachable',
 'The cloud provider instance metadata service is reachable — an SSRF path to IAM credential theft.',
 'critical', 'Enforce IMDSv2 or equivalent token-bound metadata access; block app-layer requests to the metadata IP unless required.',
 '{"target":"service","all":[{"field":"protocol_family","operator":"eq","value":"cloud-metadata"}]}'),

('iam-privileged-role-exposed', 'High-criticality asset with reachable cloud metadata',
 'A high/critical-criticality asset can reach cloud instance metadata — its attached IAM role should be reviewed for least-privilege.',
 'high', 'Review the IAM role/service account attached to this instance for least-privilege.',
 '{"target":"host","all":[{"field":"device_class","operator":"eq","value":"cloud"},{"field":"criticality","operator":"in","value":["high","critical"]}]}'),

('critical-host-flat-network', 'Critical host on an unsegmented network',
 'A critical host sits on a general internal segment with no dedicated management isolation.',
 'high', 'Move critical hosts to a dedicated management/restricted VLAN with explicit firewall rules.',
 '{"target":"host","all":[{"field":"criticality","operator":"eq","value":"critical"},{"field":"network_segment.zone","operator":"eq","value":"internal"}]}')
ON CONFLICT (key) DO NOTHING;
