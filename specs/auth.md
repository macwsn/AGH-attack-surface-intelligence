---
capability: auth
title: Authentication and RBAC
code_id: AUTH
code: ["internal/auth/**", "cmd/asi/main.go"]
tests: ["internal/auth/*_test.go", "cmd/asi/main*_test.go"]
---
# Authentication and RBAC

Local accounts with argon2id passwords, server-side sessions in Postgres, role-based permissions with four built-in
roles and custom roles, an HTTP middleware enforcing sessions, permissions and CSRF, login rate limits, an audit log,
and the `asi user create` command.

## Requirements

### REQ-AUTH-001: Password hashing
The system SHALL store passwords only as argon2id PHC strings (`$argon2id$v=19$`, m >= 19456 KiB, t >= 2) with a random salt of at least 16 bytes per hash, produced by `HashPassword`, and SHALL verify them with `VerifyPassword` using a constant-time comparison of the derived keys.

#### Scenario: same password hashed twice
- WHEN the same password is hashed twice
- THEN the two encoded strings differ
- AND both verify for that password and not for a password differing in one character or in case

#### Scenario: malformed hash
- WHEN `VerifyPassword` gets a string that is not an argon2id PHC string
- THEN it returns an error

### REQ-AUTH-002: Minimum password length
The system SHALL reject passwords shorter than 12 Unicode characters (runes) with `ErrPasswordTooShort` in `HashPassword` and `Service.CreateUser`, creating nothing.

#### Scenario: length boundary
- WHEN a password of 11 characters, or the empty password, is given
- THEN the call fails with `ErrPasswordTooShort`
- AND a password of 12 characters, including 12 multi-byte characters such as "ł", is accepted

### REQ-AUTH-003: Built-in permissions and roles
After migration the system SHALL have the permissions `AllPermissions` (inventory.read, inventory.edit, inventory.create, inventory.delete, scan.run, scan.configure, signature.manage, export, import, user.manage, role.manage) and the built-in roles admin (all permissions), editor (inventory.create, inventory.delete, inventory.edit, inventory.read, import, export, scan.run, signature.manage), operator (inventory.edit, inventory.read, export) and viewer (inventory.read); re-running the migration SHALL change nothing.

#### Scenario: fresh schema
- WHEN `asi migrate` runs on an empty schema
- THEN `Service.ListRoles` returns the four built-in roles with `Builtin` true and the permission sets above

### REQ-AUTH-004: Built-in roles are immutable
The system SHALL refuse to update or delete the built-in roles admin, editor, operator and viewer with `ErrBuiltinRole`, leaving them unchanged. Decision: built-in roles are immutable (not only undeletable), so their permission sets always match docs/architecture.md.

#### Scenario: update a built-in role
- WHEN `Service.UpdateRole` or `Service.DeleteRole` is called for "viewer"
- THEN it fails with `ErrBuiltinRole` and the role keeps its permissions

### REQ-AUTH-005: Custom roles
The system SHALL let custom roles be created (`Service.CreateRole`), have their permission set replaced (`Service.UpdateRole`) and be deleted (`Service.DeleteRole`); it SHALL fail with `ErrRoleExists` for a duplicate name, `ErrUnknownPermission` for a permission outside `AllPermissions`, `ErrUnknownRole` for an unknown role and `ErrRoleInUse` when deleting a role still assigned to a user.

#### Scenario: delete a role in use
- WHEN a custom role assigned to a user is deleted
- THEN the call fails with `ErrRoleInUse` and the role remains

### REQ-AUTH-006: One role per user
The system SHALL give every user exactly one existing role: `Service.CreateUser` fails with `ErrUnknownRole` for an unknown role and `ErrUserExists` for a duplicate username, `Service.SetUserRole` replaces the role, and the users role column is NOT NULL with a foreign key to roles.

#### Scenario: change a user's role
- WHEN `Service.SetUserRole` sets "operator" on a viewer
- THEN `Service.GetUser` reports the role "operator" only

### REQ-AUTH-007: Server-side sessions
On successful `Service.Login` the system SHALL create a session in Postgres whose token is 32 random bytes encoded as unpadded base64url, SHALL store only the SHA-256 of the token, and SHALL return a per-session CSRF token; `Service.LookupSession` SHALL return the `Principal` (username, role, permissions, CSRF token) or `ErrNoSession` for an unknown or garbled token.

#### Scenario: stored hashed
- WHEN a user logs in
- THEN no column of the sessions row equals the raw token, and a row keyed by sha256(token) exists

### REQ-AUTH-008: Session expiry and logout
The system SHALL expire a session after `Config.IdleTimeout` (default 30 minutes) without a successful lookup and after `Config.AbsoluteTimeout` (default 12 hours) since login regardless of use; `Service.Logout` SHALL invalidate the session and SHALL not fail for an unknown token.

#### Scenario: absolute expiry
- WHEN a session is looked up every IdleTimeout/2
- THEN lookups fail with `ErrNoSession` once AbsoluteTimeout has passed since login

### REQ-AUTH-009: Session cookie
The system SHALL send the session in cookie `asi_session` with Path "/", HttpOnly, SameSite=Lax, and Secure exactly when the request arrived over TLS (`Service.SetSessionCookie`); `Service.ClearSessionCookie` SHALL expire it with the same attributes.

#### Scenario: plain HTTP
- WHEN the cookie is set on a request without TLS
- THEN Secure is false and HttpOnly and SameSite=Lax are set

### REQ-AUTH-010: Permission middleware
`Service.RequirePermission` SHALL answer 401 when the request has no valid session (missing, unknown, expired or logged-out token), 403 when the session's role lacks the permission, and otherwise call the handler with the `Principal` available through `PrincipalFrom`.

#### Scenario: viewer edits inventory
- WHEN a viewer session requests a handler guarded by inventory.edit
- THEN the response is 403 and the handler is not called

### REQ-AUTH-011: CSRF protection
Behind `Service.RequirePermission`, the system SHALL reject every POST, PUT, PATCH and DELETE request with 403 unless it carries the session's CSRF token in header `X-CSRF-Token` or form field `csrf_token`, compared in constant time; GET requests need no token, and the session check (401) precedes the CSRF check. Decision: the token is passed in the `X-CSRF-Token` header or the `csrf_token` form field.

#### Scenario: another session's token
- WHEN a POST carries the CSRF token of a different session
- THEN the response is 403 and the handler is not called

### REQ-AUTH-012: Login rate limits
The system SHALL refuse logins with `ErrRateLimited`, even with the correct password, after `Config.AccountLimit` (default 5) failed logins for the same username or `Config.AddressLimit` (default 20) failed logins from the same address within `Config.LimitWindow` (default 15 minutes); nonexistent usernames are limited the same way, and a successful login resets the username's failures. Decision: the limiter state is in memory and belongs to each `Service` instance (no package-level state, not shared across processes, reset on restart).

#### Scenario: address limit
- WHEN 20 failed logins come from address A over different usernames
- THEN a correct login from A is refused and the same login from address B succeeds

### REQ-AUTH-013: Indistinguishable login failures
The system SHALL fail a wrong password for an existing user and any password for a nonexistent user with the same `ErrInvalidCredentials` error text, and SHALL run an argon2id verification against a dummy hash for a nonexistent user so both paths cost about the same time.

#### Scenario: nonexistent user
- WHEN a login names a user that does not exist
- THEN the error equals the wrong-password error and the call takes comparable time

### REQ-AUTH-014: Audit log
The system SHALL add exactly one audit_log row (at set by the server, actor, action, target, address) for: successful login ("login"), failed or rate-limited login ("login_failed", actor = submitted username), logout ("logout"), user changes ("user.create", "user.update", "user.delete") and role changes ("role.create", "role.update", "role.delete") with the acting user and address and the affected name as target; rejected operations add no user./role. row, and no row contains a password or session token.

#### Scenario: failed login
- WHEN a login fails for username "mallory" from 10.0.0.9
- THEN one row with action "login_failed", actor "mallory" and address "10.0.0.9" is added

### REQ-AUTH-015: Last admin protection
The system SHALL refuse to delete or demote the last user with role admin with `ErrLastAdmin`, checking within the same transaction under a lock so that concurrent demotions leave at least one admin; unknown users fail with `ErrUnknownUser`.

#### Scenario: two concurrent demotions
- WHEN the last two admins are demoted concurrently
- THEN at least one admin remains

### REQ-AUTH-016: `asi user create`
`asi user create --username U --role R --password-stdin` SHALL read one line from stdin, strip one trailing "\n" or "\r\n" and nothing else, create the user through `Service.CreateUser` with audit actor "cli" and address "local", print one line naming the user and exit 0; errors (user exists, password shorter than 12 characters, unknown role) SHALL print one line on stderr and exit 1, missing --username or --role SHALL print the usage to stderr and exit 2, and without --password-stdin it SHALL exit 1 with a one-line error telling to use --password-stdin, never prompting. Decision: the CLI audit actor is "cli" and the address "local".

#### Scenario: create an admin
- WHEN `printf 'correct-horse-battery\n' | asi user create --username alice --role admin --password-stdin` runs on a migrated database
- THEN it exits 0, prints a line containing "alice", alice can log in, and an audit row "user.create" with actor "cli", address "local" and target "alice" exists

#### Scenario: duplicate user
- WHEN the same command runs again
- THEN it exits 1 with a one-line stderr error that the user exists
