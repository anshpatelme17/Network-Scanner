\set ON_ERROR_STOP on
-- SEC-02 role and ownership provisioning for the verified security_platform
-- inventory. Review the preflight against the current catalog before use.
-- This script is intentionally one-shot: it stops if roles already exist or
-- the catalog differs, instead of guessing or partially provisioning.
-- Run with psql as secuser against security_platform. Do not pass passwords
-- through psql arguments or place them in this file. Set login passwords in a
-- separate approved secret workflow before mounting the corresponding files.

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

DO $preflight$
DECLARE
    expected_tables text[] := ARRAY[
        'alembic_version', 'assets', 'auth_audits', 'correlation_audits',
        'correlation_evidence', 'correlations', 'discovered_services',
        'event_audits', 'incident_audits', 'incident_evidence', 'incident_relationships',
        'incidents', 'ingestion_checkpoints', 'response_actions', 'response_audit',
        'response_executions', 'response_rollbacks', 'revoked_tokens', 'risk_assessments',
        'risk_audits', 'scan_audit', 'scan_jobs', 'security_events', 'users',
        'vulnerabilities', 'vulnerability_audits'
    ];
    expected_audits text[] := ARRAY[
        'auth_audits', 'correlation_audits', 'event_audits', 'incident_audits',
        'response_audit', 'risk_audits', 'scan_audit', 'vulnerability_audits'
    ];
    actual_count integer;
BEGIN
    IF current_database() <> 'security_platform' THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: connected database name mismatch';
    END IF;
    IF current_user <> 'secuser'
       OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: connect as the secuser administrator';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_database d
        JOIN pg_roles r ON r.oid = d.datdba
        WHERE d.datname = current_database() AND r.rolname = 'secuser'
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: database owner must be secuser';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_namespace n
        JOIN pg_roles r ON r.oid = n.nspowner
        WHERE n.nspname = 'public' AND r.rolname = 'pg_database_owner'
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: public schema owner must be pg_database_owner';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname IN ('sec_owner', 'sec_migrator', 'sec_runtime')
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: a target role already exists; inspect it first';
    END IF;

    -- Revoking PUBLIC database access below would affect any other login.
    -- Stop for manual review if this database has another login principal.
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolcanlogin AND rolname <> current_user
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: review other login roles before revoking PUBLIC access';
    END IF;

    -- Explicit target roles are absent (checked above), so they cannot inherit
    -- privileges through pre-existing memberships. The existing catalog must
    -- also have no unreviewed direct ACL grantees that this script would alter.
    IF EXISTS (
        SELECT 1
        FROM pg_database d
        CROSS JOIN LATERAL aclexplode(
            COALESCE(d.datacl, acldefault('d', d.datdba))
        ) acl
        WHERE d.datname = current_database()
          AND acl.grantee <> 0
          AND acl.grantee NOT IN (
              d.datdba,
              (SELECT oid FROM pg_roles WHERE rolname = current_user)
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_database d
        CROSS JOIN LATERAL aclexplode(
            COALESCE(d.datacl, acldefault('d', d.datdba))
        ) acl
        WHERE d.datname = current_database()
          AND acl.grantee = 0
          AND (acl.privilege_type = 'CREATE' OR acl.is_grantable)
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: database ACLs require explicit review';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(
            COALESCE(n.nspacl, acldefault('n', n.nspowner))
        ) acl
        WHERE n.nspname = 'public'
          AND acl.grantee <> 0
          AND acl.grantee NOT IN (
              n.nspowner,
              (SELECT oid FROM pg_roles WHERE rolname = current_user)
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(
            COALESCE(n.nspacl, acldefault('n', n.nspowner))
        ) acl
        WHERE n.nspname = 'public'
          AND acl.grantee = 0
          AND (acl.is_grantable OR acl.privilege_type = 'CREATE')
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: public schema ACLs require explicit review';
    END IF;

    SELECT count(*) INTO actual_count
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND c.relname = ANY(expected_tables);
    IF actual_count <> cardinality(expected_tables)
       OR EXISTS (
            SELECT 1
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
              AND NOT (c.relname = ANY(expected_tables))
       ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: application table inventory mismatch';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'i'
          AND pg_get_userbyid(c.relowner) <> 'secuser'
    ) OR (
        SELECT count(*)
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'i'
    ) <> 123 THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: public index inventory or ownership mismatch';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
          AND pg_get_userbyid(c.relowner) <> 'secuser'
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: application table owner mismatch';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(c.relacl, acldefault('r', c.relowner))
        ) acl
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND acl.grantee NOT IN (
              c.relowner,
              (SELECT oid FROM pg_roles WHERE rolname = current_user)
          )
    ) OR EXISTS (
        SELECT 1
        FROM information_schema.column_privileges
        WHERE table_schema = 'public' AND grantee <> 'secuser'
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: table or column ACLs require explicit review';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('S', 'v', 'm', 'f')
    ) OR EXISTS (
        SELECT 1
        FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
        WHERE n.nspname = 'public'
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: unreviewed sequence, view, foreign table, or extension in public';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND (c.relrowsecurity OR c.relforcerowsecurity)
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: row-level security requires separate review';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.oid <> to_regprocedure('public.audit_append_only_guard()')
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: additional public functions require review';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.oid = to_regprocedure('public.audit_append_only_guard()')
          AND pg_get_userbyid(p.proowner) = 'secuser'
          AND NOT p.prosecdef
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: audit guard function owner/security mismatch';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(p.proacl, acldefault('f', p.proowner))
        ) acl
        WHERE n.nspname = 'public'
          AND p.oid = to_regprocedure('public.audit_append_only_guard()')
          AND acl.grantee <> 0
          AND acl.grantee NOT IN (
              p.proowner,
              (SELECT oid FROM pg_roles WHERE rolname = current_user)
          )
    ) OR EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(
            COALESCE(p.proacl, acldefault('f', p.proowner))
        ) acl
        WHERE n.nspname = 'public'
          AND p.oid = to_regprocedure('public.audit_append_only_guard()')
          AND acl.grantee = 0
          AND (acl.privilege_type <> 'EXECUTE' OR acl.is_grantable)
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: audit function ACLs require explicit review';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_default_acl
        WHERE defaclnamespace = 0
           OR defaclnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: existing global or public default ACLs require explicit review';
    END IF;

    SELECT count(DISTINCT c.relname) INTO actual_count
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(expected_audits)
      AND NOT t.tgisinternal
      AND t.tgenabled = 'O'
      AND t.tgtype = 27
      AND t.tgfoid = to_regprocedure('public.audit_append_only_guard()');
    IF actual_count <> cardinality(expected_audits)
       OR (
            SELECT count(*)
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND NOT t.tgisinternal
       ) <> cardinality(expected_audits) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: audit trigger inventory mismatch';
    END IF;
END
$preflight$;

-- Database and public schema ownership are intentionally preserved.
-- The NOLOGIN owner receives only the schema rights required for Alembic DDL.
CREATE ROLE sec_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE sec_migrator
    LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE sec_runtime
    LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT sec_owner TO sec_migrator WITH INHERIT FALSE, SET TRUE;

DO $role_validation$
BEGIN
    IF (
        SELECT count(*)
        FROM pg_auth_members m
        JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname IN ('sec_owner', 'sec_migrator', 'sec_runtime')
           OR member_role.rolname IN ('sec_owner', 'sec_migrator', 'sec_runtime')
    ) <> 1 OR NOT EXISTS (
        SELECT 1
        FROM pg_auth_members m
        JOIN pg_roles granted_role ON granted_role.oid = m.roleid
        JOIN pg_roles member_role ON member_role.oid = m.member
        WHERE granted_role.rolname = 'sec_owner'
          AND member_role.rolname = 'sec_migrator'
          AND NOT m.inherit_option
          AND m.set_option
          AND NOT m.admin_option
    ) THEN
        RAISE EXCEPTION 'SEC-02 provisioning stopped: role membership is not least-privilege';
    END IF;
END
$role_validation$;

REVOKE CONNECT, TEMPORARY ON DATABASE security_platform FROM PUBLIC;
GRANT CONNECT ON DATABASE security_platform TO sec_migrator, sec_runtime;

-- Revoke CREATE from PUBLIC but retain the reviewed PUBLIC USAGE privilege.
REVOKE CREATE ON SCHEMA public FROM PUBLIC, sec_migrator, sec_runtime;
GRANT USAGE, CREATE ON SCHEMA public TO sec_owner;
GRANT USAGE ON SCHEMA public TO sec_runtime;

-- ALTER TABLE OWNER transfers ownership of the dependent indexes and
-- constraints. Triggers follow their table; the trigger function is separate.
ALTER TABLE public.alembic_version OWNER TO sec_owner;
ALTER TABLE public.assets OWNER TO sec_owner;
ALTER TABLE public.auth_audits OWNER TO sec_owner;
ALTER TABLE public.correlation_audits OWNER TO sec_owner;
ALTER TABLE public.correlation_evidence OWNER TO sec_owner;
ALTER TABLE public.correlations OWNER TO sec_owner;
ALTER TABLE public.discovered_services OWNER TO sec_owner;
ALTER TABLE public.event_audits OWNER TO sec_owner;
ALTER TABLE public.incident_audits OWNER TO sec_owner;
ALTER TABLE public.incident_evidence OWNER TO sec_owner;
ALTER TABLE public.incident_relationships OWNER TO sec_owner;
ALTER TABLE public.incidents OWNER TO sec_owner;
ALTER TABLE public.ingestion_checkpoints OWNER TO sec_owner;
ALTER TABLE public.response_actions OWNER TO sec_owner;
ALTER TABLE public.response_audit OWNER TO sec_owner;
ALTER TABLE public.response_executions OWNER TO sec_owner;
ALTER TABLE public.response_rollbacks OWNER TO sec_owner;
ALTER TABLE public.revoked_tokens OWNER TO sec_owner;
ALTER TABLE public.risk_assessments OWNER TO sec_owner;
ALTER TABLE public.risk_audits OWNER TO sec_owner;
ALTER TABLE public.scan_audit OWNER TO sec_owner;
ALTER TABLE public.scan_jobs OWNER TO sec_owner;
ALTER TABLE public.security_events OWNER TO sec_owner;
ALTER TABLE public.users OWNER TO sec_owner;
ALTER TABLE public.vulnerabilities OWNER TO sec_owner;
ALTER TABLE public.vulnerability_audits OWNER TO sec_owner;
ALTER FUNCTION public.audit_append_only_guard() OWNER TO sec_owner;

-- Remove PUBLIC and any direct runtime/migrator table rights before applying
-- the reviewed runtime matrix. There are deliberately no runtime defaults.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, sec_runtime, sec_migrator;
REVOKE ALL PRIVILEGES ON FUNCTION public.audit_append_only_guard()
    FROM PUBLIC, sec_runtime, sec_migrator;

GRANT SELECT, INSERT, UPDATE ON TABLE
    public.assets,
    public.scan_jobs,
    public.security_events,
    public.correlations,
    public.correlation_evidence,
    public.incidents,
    public.response_actions,
    public.users,
    public.vulnerabilities,
    public.ingestion_checkpoints
TO sec_runtime;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    public.risk_assessments,
    public.incident_relationships
TO sec_runtime;

GRANT SELECT, INSERT, DELETE ON TABLE public.discovered_services TO sec_runtime;

GRANT SELECT, INSERT ON TABLE
    public.scan_audit,
    public.event_audits,
    public.correlation_audits,
    public.risk_audits,
    public.incident_audits,
    public.response_audit,
    public.auth_audits,
    public.vulnerability_audits,
    public.incident_evidence,
    public.response_executions,
    public.response_rollbacks,
    public.revoked_tokens
TO sec_runtime;

REVOKE ALL PRIVILEGES ON TABLE public.alembic_version FROM PUBLIC, sec_runtime;

-- Default ACLs apply to objects created while current_user is sec_owner.
-- Do not give the runtime role blanket privileges on future objects.
SET ROLE sec_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE sec_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE sec_owner
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, sec_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE sec_owner
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, sec_runtime;
RESET ROLE;

COMMIT;

-- After this transaction commits, set passwords using the approved secret
-- workflow and create the three protected files referenced by Compose. Do not
-- start the backend until runtime credentials and grants have been verified.
