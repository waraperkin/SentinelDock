-- Seeds the DevOps/CI-CD exposure policy added in policies/devops-cicd-exposed.yaml.

INSERT INTO policies (key, name, description, severity, recommendation, conditions) VALUES
('devops-cicd-exposed', 'CI/CD service exposed publicly',
 'A CI/CD orchestration service is reachable publicly — a direct path to supply-chain compromise.',
 'critical', 'Restrict CI/CD tooling to an internal network or VPN-only access; rotate pipeline credentials if exposure was exploitable.',
 '{"target":"service","all":[{"field":"exposed_publicly","operator":"eq","value":true}],"any":[{"field":"name","operator":"contains","value":"jenkins"},{"field":"name","operator":"contains","value":"gitlab-runner"},{"field":"port","operator":"eq","value":50000}]}')
ON CONFLICT (key) DO NOTHING;
