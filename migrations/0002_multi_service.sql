-- v2: keys are service + label + website + secret. No stored repo/branch/path policy.
-- Grants authorize agent + service + key label for 2 hours; what Pi may do is said in chat.
ALTER TABLE keys ADD COLUMN website TEXT NOT NULL DEFAULT '';
ALTER TABLE keys DROP COLUMN policy_json;
ALTER TABLE agents DROP COLUMN policy_json;
ALTER TABLE grants DROP COLUMN policy_json;
