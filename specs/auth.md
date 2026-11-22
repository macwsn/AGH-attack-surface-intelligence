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
The system SHALL add exactly one audit_log row (at set by the server, actor, action, target, address) for: successful login ("login"), failed or rate-limited login ("login_failed", actor = submitted username), logout ("logout"), user changes ("user.create", "user.update", "user.delete", "user.password", "user.disable", "user.enable") and role changes ("role.create", "role.update", "role.delete") with the acting user and address and the affected name as target; rejected operations add no user./role. row, and no row contains a password or session token.

#### Scenario: failed login
- WHEN a login fails for username "mallory" from 10.0.0.9
- THEN one row with action "login_failed", actor "mallory" and address "10.0.0.9" is added

### REQ-AUTH-015: Last admin protection
The system SHALL refuse to delete, demote or disable the last enabled user whose role holds every permission (the
built-in admin role or any custom role with all permissions) with `ErrLastAdmin` ("the last enabled admin cannot be
deleted, demoted or disabled"), counting only enabled users whose role holds every permission and checking within the
same transaction under the same advisory lock for `SetUserRole`, `DeleteUser` and `SetUserDisabled`, so that
concurrent changes leave at least one enabled user holding every permission; moving such a user to another role that
holds every permission is not a demotion; a disabled admin may be demoted or deleted freely; unknown users fail with
`ErrUnknownUser`.

#### Scenario: two concurrent demotions
- WHEN the last two admins are demoted concurrently
- THEN at least one admin remains

#### Scenario: disabled second admin
- WHEN root and root2 are admins and root2 is disabled
- THEN disabling, demoting or deleting root fails with `ErrLastAdmin`, and demoting or deleting root2 succeeds

#### Scenario: custom all-permission role
- WHEN the only user is "su" with a custom role holding every permission
- THEN disabling, deleting or demoting su to a role missing any permission fails with `ErrLastAdmin`

### REQ-AUTH-016: `asi user create`
`asi user create --username U --role R --password-stdin` SHALL read one line from stdin, strip one trailing "\n" or "\r\n" and nothing else, create the user through `Service.CreateUser` with audit actor "cli" and address "local", print one line naming the user and exit 0; errors (user exists, password shorter than 12 characters, unknown role) SHALL print one line on stderr and exit 1, missing --username or --role SHALL print the usage to stderr and exit 2, and without --password-stdin it SHALL exit 1 with a one-line error telling to use --password-stdin, never prompting. Decision: the CLI audit actor is "cli" and the address "local".

#### Scenario: create an admin
- WHEN `printf 'correct-horse-battery\n' | asi user create --username alice --role admin --password-stdin` runs on a migrated database
- THEN it exits 0, prints a line containing "alice", alice can log in, and an audit row "user.create" with actor "cli", address "local" and target "alice" exists

#### Scenario: duplicate user
- WHEN the same command runs again
- THEN it exits 1 with a one-line stderr error that the user exists

### REQ-AUTH-017: List users
`Service.ListUsers` SHALL return every user with username, role, `Disabled` flag and creation time, ordered by
username; `User` and `Service.GetUser` SHALL carry the `Disabled` flag (`users.disabled`, migration
`0017_user_disabled.sql`, default false).

#### Scenario: list with a disabled user
- WHEN users root (admin), alice (editor) and bob (viewer, disabled) exist
- THEN `ListUsers` returns alice, bob, root in that order with bob marked disabled

### REQ-AUTH-018: Reset password
`Service.ResetPassword(actor, username, password)` SHALL replace the user's argon2id hash, enforce the same minimum
length as `HashPassword` (`ErrPasswordTooShort`), fail with `ErrUnknownUser` for an unknown user, delete all of the
user's sessions and add one audit row "user.password" with the user as target, all in one transaction; the password is
never written to the audit log; signed-in actors are limited by REQ-AUTH-026 and cannot reset their own password.
`Service.ResetPasswordKeepSession(actor, username, password, session)` SHALL do the same but, when an exempt actor
resets the password of the user it is named after, keep the session whose token is `session`; the Users page uses it
with the request's session cookie.

#### Scenario: reset
- WHEN an admin resets alice's password
- THEN alice can log in with the new password only, and one "user.password" row targeting alice is added

#### Scenario: reset ends sessions
- WHEN an admin resets the password of a viewer who is signed in
- THEN the viewer's next request with the old session cookie is redirected to `/login`, and other users stay signed in

#### Scenario: own password through the Users page
- WHEN a signed-in admin posts a new password to their own `/users/<name>/password`
- THEN the answer is 403 pointing to the Account page, the password and all sessions are unchanged and no audit row
  is added

### REQ-AUTH-019: Disable and enable users
`Service.SetUserDisabled(actor, username, disabled)` SHALL set the user's disabled flag and add one audit row
"user.disable" or "user.enable"; disabling SHALL delete all of the user's sessions. A disabled user's login SHALL fail
with `ErrInvalidCredentials` (audited as "login_failed", password still verified so the timing is unchanged), and
`LookupSession` SHALL return `ErrNoSession` for a session whose user is disabled. Unknown users fail with
`ErrUnknownUser`.

#### Scenario: disable a logged-in user
- WHEN alice has a session and an admin disables alice
- THEN the session no longer works and alice cannot log in until she is enabled again

### REQ-AUTH-020: Audit query
`Service.ListAudit(filter, offset, limit)` SHALL return audit entries (id, at, actor, action, target, address)
matching all set fields of `AuditFilter` (`Actor`, `Action`, `Target` exact match; `Since` inclusive, `Until`
exclusive), newest first (ties by id, newest first), skipping `offset` and returning at most `limit` entries, plus the
total number of matching entries; a negative offset or a limit below 1 is an error.

#### Scenario: second page
- WHEN 7 entries exist and `ListAudit({}, 3, 3)` is called
- THEN the 4th to 6th newest entries are returned with total 7

### REQ-AUTH-021: `asi user list|set-role|delete` and `asi role list`
`asi user list` SHALL print a header and one line per user (username, role, enabled/disabled, creation time in
RFC 3339 UTC); `asi user set-role --username U --role R` and `asi user delete --username U` SHALL call
`Service.SetUserRole` / `Service.DeleteUser` with audit actor "cli" and address "local" and print one line naming the
user; `asi role list` SHALL print a header and one line per role (name, built-in true/false, comma-separated
permissions). Errors (unknown user, unknown role, `ErrLastAdmin`) SHALL print one line on stderr and exit 1; missing
or extra arguments SHALL print the usage to stderr and exit 2. The usage text lists these commands. None of them runs
on `asi serve` startup.

#### Scenario: demote the last admin from the CLI
- WHEN `asi user set-role --username root --role viewer` runs and root is the only enabled admin
- THEN it exits 1, stderr is `asi user: the last enabled admin cannot be deleted, demoted or disabled`, and no audit
  row is added

### REQ-AUTH-023: Change own password
`Service.ChangePassword(actor, current, password, session)` SHALL let the actor change their own password: it SHALL
reject a new password under 12 characters (`ErrPasswordTooShort`), count the check of `current` as a login attempt of
the actor's username and address in the failed-login throttle (`ErrRateLimited` when the limit is reached, a
"login_failed" audit row and `ErrInvalidCredentials` when `current` is wrong), reject a new password equal to the
current one (`ErrSamePassword`), and otherwise, in one transaction, store the new argon2id hash, delete every session
of the user except the one whose token is `session`, and add one audit row "user.password" with the user as actor and
target; no password material is written to the audit log. The admin reset (REQ-AUTH-018) is unchanged.

#### Scenario: other sessions end
- WHEN a viewer signed in twice changes their password from one session
- THEN that session stays signed in, the other is redirected to `/login`, and only the new password works

#### Scenario: wrong current password is throttled
- WHEN a user submits a wrong current password as often as the account limit allows
- THEN their next login with the right password fails with `ErrRateLimited` and the password is unchanged

### REQ-AUTH-022: CSRF token stored hashed
The CSRF token of a session SHALL be derived from the session token (HMAC-SHA-256) and the sessions table SHALL store
only its SHA-256 (`sessions.csrf_hash`); `Service.LookupSession` SHALL derive the token again and return it in the
`Principal` only when it matches the stored hash. Migration `0020` SHALL end all existing sessions, whose CSRF tokens
were stored in plain text.

#### Scenario: no plain CSRF token in the database
- WHEN a user logs in
- THEN the sessions row contains neither the CSRF token nor its hex form, but its SHA-256
- AND `LookupSession` returns the same CSRF token as `Login`

### REQ-AUTH-024: Role assignment needs the assigned permissions
When the actor is a signed-in user, `Service.SetUserRole` and `Service.CreateUser` SHALL fail with
`ErrPermissionNotHeld` unless the actor's own role holds every permission of the role being assigned (so only a role
holding every permission can assign admin), and `Service.SetUserRole` SHALL fail with `ErrOwnRole` when the actor
changes their own role, to any role, and with `ErrStrongerUser` (REQ-AUTH-026) when the target's current role holds a
permission the actor's role does not. The actor's role is read inside the same transaction as the change; a rejected
call changes nothing and writes no audit row. `ErrLastAdmin` (REQ-AUTH-015) is checked first and applies to every
actor. An actor is a signed-in user when its address is not "local" and either the request context carries its
`Principal` (set by the session middleware) or the user has a session; a signed-in principal whose user no longer
exists holds no permissions. Decision: actors with address "local" (the CLI actor "cli" of REQ-AUTH-021, setup and
test actors) and actors that are not signed-in users hold no role and are exempt from the hold and own-role rules,
so `asi user set-role` still sets any role; web actors always carry the request's client address. The web UI SHALL
answer these errors with 403 and the users page naming the problem.

#### Scenario: user manager assigns a stronger role
- WHEN a signed-in user whose role holds only user.manage sets "editor" on a viewer or creates a user with role "admin"
- THEN the call fails with `ErrPermissionNotHeld` (HTTP 403), the viewer keeps "viewer", no user is created and no
  audit row is added

#### Scenario: self-promotion
- WHEN that user sets any role, including a weaker one, on themselves
- THEN the call fails with `ErrOwnRole` (HTTP 403) and their role is unchanged

#### Scenario: legal assignment
- WHEN that user sets a role with no permissions on another user whose role holds only user.manage, or an admin sets
  "editor" on another user
- THEN the role is changed (HTTP 303)

#### Scenario: CLI actor
- WHEN `asi user set-role` sets "admin" on a viewer
- THEN the role is changed; demoting the last enabled admin still fails with `ErrLastAdmin`

### REQ-AUTH-025: Role edits only with held permissions
When the actor is a signed-in user (REQ-AUTH-024), `Service.CreateRole` and `Service.UpdateRole` SHALL fail with
`ErrPermissionNotHeld` when the submitted permission set contains a permission the actor's own role does not hold,
and `Service.UpdateRole` and `Service.DeleteRole` SHALL fail with `ErrOwnRole` for the role the actor currently has,
whatever permissions are submitted. Built-in roles keep failing with `ErrBuiltinRole` (REQ-AUTH-004) for every actor,
and that check comes first. A rejected call changes nothing and writes no audit row. The web UI SHALL answer these
errors with 403 and the roles page naming the problem, and SHALL parse the role form (body bounded like the other
forms, 400 when it cannot be read) before reading the ticked permissions, so a POST carrying the CSRF token only in
the `X-CSRF-Token` header keeps the submitted permissions.

#### Scenario: role manager grants an unheld permission
- WHEN a signed-in user whose role holds only role.manage creates role "evil" with user.manage, or gives
  inventory.read to a custom role
- THEN the call fails with `ErrPermissionNotHeld` (HTTP 403), "evil" does not exist and the other role is unchanged

#### Scenario: own role
- WHEN that user updates or deletes their own role
- THEN the call fails with `ErrOwnRole` (HTTP 403) and the role keeps [role.manage]

#### Scenario: held permission
- WHEN that user gives role.manage to another custom role
- THEN the role is saved (HTTP 303)

#### Scenario: CSRF token in the header
- WHEN an admin posts the role form with perm=export and perm=inventory.read and the CSRF token only in `X-CSRF-Token`
- THEN the role has exactly [export, inventory.read]

### REQ-AUTH-026: User actions only on users the actor fully holds
When the actor is a signed-in user (REQ-AUTH-024), `Service.ResetPassword`, `Service.ResetPasswordKeepSession`,
`Service.SetUserDisabled` (disable and enable), `Service.DeleteUser` and `Service.SetUserRole` SHALL fail with
`ErrStrongerUser` unless the actor's own role holds every permission of the target user's current role, with no
exception for any permission (a user manager who should manage viewers needs inventory.read as well);
`SetUserRole` additionally keeps the REQ-AUTH-024 rules for the new role. Resetting the password of, disabling,
enabling or deleting oneself SHALL fail with `ErrOwnAccount`; the own password is changed only through
`Service.ChangePassword` (REQ-AUTH-023, `/account`). The target is read and locked inside the same transaction as the
change; `ErrLastAdmin` (REQ-AUTH-015) is checked first; a rejected call changes nothing and writes no audit row.
Actors with address "local" (the CLI actor "cli") are exempt, as in REQ-AUTH-024. The web UI SHALL answer these errors
with 403 and the users page naming the problem, and SHALL show the role, password and action controls only on rows
the signed-in user may act on (plain text otherwise, with a link to `/account` on their own row), with one sentence
saying that only users whose role the signed-in user fully holds can be managed.

#### Scenario: user manager resets the admin's password
- WHEN a signed-in user whose role holds only user.manage posts a new password to `/users/admin/password`
- THEN the answer is 403, the admin's password is unchanged and no audit row is added

#### Scenario: target without inventory.read is managed
- WHEN that user resets the password of, disables, deletes or sets role "nobody" on a user whose role holds only
  user.manage
- THEN the change is made

#### Scenario: viewer needs inventory.read
- WHEN that user acts on a viewer
- THEN the call fails with `ErrStrongerUser`; with a role holding user.manage and inventory.read it succeeds

#### Scenario: self
- WHEN a signed-in user, admin included, resets their own password, disables or deletes themselves through `/users`
- THEN the call fails with `ErrOwnAccount` (HTTP 403) and nothing changes

#### Scenario: operator on the host
- WHEN `asi user set-role` or `asi user delete` targets an admin while another all-permission user remains
- THEN the change is made

