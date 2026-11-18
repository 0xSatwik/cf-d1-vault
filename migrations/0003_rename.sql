-- v3: allow renaming a key label. id and service stay immutable.
-- The label is part of the encryption AAD, so a rename must decrypt with
-- the old label and re-encrypt with the new one (done by the rename action
-- in admin.ts, never by a bare UPDATE here).
DROP TRIGGER key_identity_immutable;
CREATE TRIGGER key_identity_immutable BEFORE UPDATE OF id,service ON keys
BEGIN SELECT RAISE(ABORT,'key identity immutable'); END;
