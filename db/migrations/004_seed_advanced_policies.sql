-- Seeds the advanced policies added in policies/*.yaml (sensitive WAN ports,
-- OT/IT segmentation). Mirrors 002_seed_policies.sql's approach.

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('sensitive-ports-exposed-wan', 'Sensitive administrative port exposed to the WAN',
 'Telnet and RDP should never be reachable from outside the network.',
 'critical', 'Remove any public/WAN exposure for these ports; use a VPN or bastion instead.',
 '{"target":"service","all":[{"field":"exposed_publicly","operator":"eq","value":true}],"any":[{"field":"port","operator":"eq","value":23},{"field":"port","operator":"eq","value":3389}]}'),

('ot-it-segmentation', 'OT/ICS host placed on an IT network segment',
 'OT/ICS hosts must be isolated from general-purpose IT network segments.',
 'critical', 'Move the host to a dedicated OT/ICS segment with a firewall or data diode to IT.',
 '{"target":"host","all":[{"field":"role","operator":"in","value":["ot","ics","scada","plc"]},{"field":"network_segment.zone","operator":"eq","value":"internal"}]}')
ON CONFLICT (key) DO NOTHING;
