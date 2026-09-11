-- Seeds the example policies shipped in /policies as JSON. This keeps a
-- working default policy set available on first boot; the YAML files remain
-- the human-editable source of truth and can be re-synced via the
-- /policies API.

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('ssh-exposed-public', 'SSH exposed to the public internet',
 'Detects any service on port 22 bound to a wildcard address and marked as publicly exposed.',
 'critical', 'Bind SSH to an internal-only interface or restrict access through a bastion host / VPN.',
 '{"target":"service","all":[{"field":"port","operator":"eq","value":22},{"field":"exposed_publicly","operator":"eq","value":true}]}'),

('docker-socket-exposed', 'Docker socket exposed via a service',
 'Flags any service reachable on the Docker daemon API ports (2375/2376).',
 'critical', 'Never expose the Docker socket over the network; use an authenticated TLS socket proxy.',
 '{"target":"service","any":[{"field":"port","operator":"eq","value":2375},{"field":"port","operator":"eq","value":2376}]}'),

('database-publicly-reachable', 'Database port reachable from a public segment',
 'Databases should never be publicly exposed.',
 'high', 'Move the database host to an internal segment and disable public exposure.',
 '{"target":"service","all":[{"field":"exposed_publicly","operator":"eq","value":true}],"any":[{"field":"port","operator":"eq","value":5432},{"field":"port","operator":"eq","value":3306},{"field":"port","operator":"eq","value":6379},{"field":"port","operator":"eq","value":27017}]}'),

('privileged-container', 'Privileged container running',
 'Privileged containers can access host devices and break out of container isolation.',
 'high', 'Remove the --privileged flag; grant only specific capabilities via --cap-add.',
 '{"target":"container","all":[{"field":"privileged","operator":"eq","value":true},{"field":"status","operator":"eq","value":"running"}]}'),

('outdated-os-critical-host', 'Unpatched OS on a critical host',
 'Critical hosts must run a currently supported OS release.',
 'high', 'Patch the host to a supported kernel/OS release and re-run collection.',
 '{"target":"host","all":[{"field":"criticality","operator":"in","value":["high","critical"]},{"field":"os_version","operator":"contains","value":"4."}]}')
ON CONFLICT (key) DO NOTHING;
