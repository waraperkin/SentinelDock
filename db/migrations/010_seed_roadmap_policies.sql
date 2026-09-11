-- Seeds new policies added as part of the roadmap cycle (distributed
-- work-splitting / multi-layer graph / advanced vuln+ICS+cloud+DevOps /
-- zero trust / auto-policy generation). See matching policies/*.yaml files.

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('cloud-onprem-mixed-segment', 'Cloud instance sharing a segment with on-prem/IT hosts',
 'A cloud-classified host (device_class = cloud) shares a network segment with at least one host of a different device_class (on-prem IT, or ICS/OT) — a Zero Trust segmentation gap.',
 'high', 'Place cloud-connected assets on a dedicated segment (or VPC/VNet with explicit peering rules) separate from on-prem IT and ICS/OT segments, and enforce access with identity-aware proxies rather than network location alone.',
 '{"target":"host","all":[{"field":"device_class","operator":"eq","value":"cloud"},{"field":"segment_has_mixed_device_classes","operator":"eq","value":true}]}')
ON CONFLICT (key) DO NOTHING;
