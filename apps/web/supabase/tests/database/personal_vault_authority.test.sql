BEGIN;
SELECT plan(3);
SELECT ok(NOT has_function_privilege('anon', 'public.push_personal_vault(uuid,text,text,bigint)', 'EXECUTE'), 'anon cannot execute personal vault push');
SELECT ok(NOT has_function_privilege('authenticated', 'public.push_personal_vault(uuid,text,text,bigint)', 'EXECUTE'), 'authenticated cannot execute personal vault push');
SELECT ok(NOT has_table_privilege('authenticated', 'public.team_vault_blobs', 'SELECT'), 'authenticated cannot read team vault blobs');
SELECT * FROM finish();
ROLLBACK;
