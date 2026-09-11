-- Seeds the OMEGA-tier policy added in policies/git-repository-exposed.yaml.

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('git-repository-exposed', 'Exposed .git repository',
 'A web server document root is a reachable git checkout (confirmed via GET /.git/HEAD) — leaks full source history including any secrets ever committed.',
 'critical', 'Remove .git from the web root or block dotfile access; rotate any credentials ever committed, even if since removed.',
 '{"target":"service","all":[{"field":"name","operator":"eq","value":"git-exposed"}]}')
ON CONFLICT (key) DO NOTHING;
