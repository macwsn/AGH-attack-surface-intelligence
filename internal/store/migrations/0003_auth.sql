CREATE TABLE permissions (
    name text PRIMARY KEY
);

CREATE TABLE roles (
    name text PRIMARY KEY,
    builtin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_permissions (
    role text NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    permission text NOT NULL REFERENCES permissions (name),
    PRIMARY KEY (role, permission)
);

CREATE TABLE users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL REFERENCES roles (name),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX users_role_idx ON users (role);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    address text NOT NULL DEFAULT ''
);

CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL DEFAULT '',
    address text NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_at_idx ON audit_log (at);

INSERT INTO permissions (name) VALUES
    ('inventory.read'),
    ('inventory.edit'),
    ('inventory.create'),
    ('inventory.delete'),
    ('scan.run'),
    ('scan.configure'),
    ('signature.manage'),
    ('export'),
    ('import'),
    ('user.manage'),
    ('role.manage');

INSERT INTO roles (name, builtin) VALUES
    ('admin', true),
    ('editor', true),
    ('operator', true),
    ('viewer', true);

INSERT INTO role_permissions (role, permission)
SELECT 'admin', name FROM permissions;

INSERT INTO role_permissions (role, permission) VALUES
    ('editor', 'inventory.create'),
    ('editor', 'inventory.delete'),
    ('editor', 'inventory.edit'),
    ('editor', 'inventory.read'),
    ('editor', 'import'),
    ('editor', 'export'),
    ('editor', 'scan.run'),
    ('editor', 'signature.manage'),
    ('operator', 'inventory.edit'),
    ('operator', 'inventory.read'),
    ('operator', 'export'),
    ('viewer', 'inventory.read');
