//go:build integration

package auth

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func findRole(t *testing.T, s *Service, name string) (Role, bool) {
	t.Helper()
	roles, err := s.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	for _, r := range roles {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

func TestCustomRoleLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})

	perms := []Permission{PermScanRun, PermInventoryRead, PermScanRun}
	if err := s.CreateRole(ctx, testActor, "scanner", perms); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	r, ok := findRole(t, s, "scanner")
	if !ok || r.Builtin {
		t.Fatalf("scanner after create = %+v (found %v), want custom role", r, ok)
	}
	if want := sortedPerms([]Permission{PermInventoryRead, PermScanRun}); !slices.Equal(sortedPerms(r.Permissions), want) {
		t.Fatalf("scanner permissions = %v, want %v", r.Permissions, want)
	}

	if err := s.CreateRole(ctx, testActor, "scanner", nil); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("duplicate CreateRole err = %v, want ErrRoleExists", err)
	}
	if err := s.CreateRole(ctx, testActor, RoleAdmin, nil); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("CreateRole(admin) err = %v, want ErrRoleExists", err)
	}
	if err := s.CreateRole(ctx, testActor, "bad", []Permission{"inventory.nuke"}); !errors.Is(err, ErrUnknownPermission) {
		t.Fatalf("CreateRole with unknown permission err = %v, want ErrUnknownPermission", err)
	}
	if _, ok := findRole(t, s, "bad"); ok {
		t.Fatal("role with unknown permission was created")
	}

	if err := s.UpdateRole(ctx, testActor, "scanner", []Permission{PermScanConfigure}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	r, _ = findRole(t, s, "scanner")
	if !slices.Equal(r.Permissions, []Permission{PermScanConfigure}) {
		t.Fatalf("scanner permissions after update = %v, want [scan.configure]", r.Permissions)
	}
	if err := s.UpdateRole(ctx, testActor, "scanner", []Permission{PermScanRun, "bogus"}); !errors.Is(err, ErrUnknownPermission) {
		t.Fatalf("UpdateRole with unknown permission err = %v, want ErrUnknownPermission", err)
	}
	r, _ = findRole(t, s, "scanner")
	if !slices.Equal(r.Permissions, []Permission{PermScanConfigure}) {
		t.Fatalf("scanner permissions after rejected update = %v", r.Permissions)
	}
	if err := s.UpdateRole(ctx, testActor, "scanner", nil); err != nil {
		t.Fatalf("UpdateRole to empty set: %v", err)
	}
	if r, _ = findRole(t, s, "scanner"); len(r.Permissions) != 0 {
		t.Fatalf("scanner permissions = %v, want none", r.Permissions)
	}

	if err := s.UpdateRole(ctx, testActor, "ghost", nil); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("UpdateRole(unknown) err = %v, want ErrUnknownRole", err)
	}
	if err := s.DeleteRole(ctx, testActor, "ghost"); !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("DeleteRole(unknown) err = %v, want ErrUnknownRole", err)
	}

	if err := s.DeleteRole(ctx, testActor, "scanner"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if _, ok := findRole(t, s, "scanner"); ok {
		t.Fatal("scanner still listed after delete")
	}
	var leftover int
	if err := s.store.Pool.QueryRow(ctx, `SELECT count(*) FROM role_permissions WHERE role = 'scanner'`).Scan(&leftover); err != nil || leftover != 0 {
		t.Fatalf("role_permissions rows left for deleted role: %d (%v)", leftover, err)
	}
}

func TestBuiltinRoleImmutable(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	for _, name := range []string{RoleAdmin, RoleEditor, RoleOperator, RoleViewer} {
		if err := s.UpdateRole(ctx, testActor, name, []Permission{PermInventoryRead}); !errors.Is(err, ErrBuiltinRole) {
			t.Errorf("UpdateRole(%s) err = %v, want ErrBuiltinRole", name, err)
		}
		if err := s.DeleteRole(ctx, testActor, name); !errors.Is(err, ErrBuiltinRole) {
			t.Errorf("DeleteRole(%s) err = %v, want ErrBuiltinRole", name, err)
		}
	}
	checkBuiltinRoles(t, s)
}

func TestDeleteRoleInUse(t *testing.T) {
	ctx := context.Background()
	s := newTestService(t, Config{})
	if err := s.CreateRole(ctx, testActor, "auditor", []Permission{PermInventoryRead, PermExport}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	mustAddUser(t, s, "dave", "auditor")
	if u, err := s.GetUser(ctx, "dave"); err != nil || u.Role != "auditor" {
		t.Fatalf("GetUser(dave) = %+v, %v", u, err)
	}

	if err := s.DeleteRole(ctx, testActor, "auditor"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("DeleteRole(in use) err = %v, want ErrRoleInUse", err)
	}
	r, ok := findRole(t, s, "auditor")
	if !ok || len(r.Permissions) != 2 {
		t.Fatalf("auditor after rejected delete = %+v (found %v)", r, ok)
	}

	if err := s.SetUserRole(ctx, testActor, "dave", RoleViewer); err != nil {
		t.Fatalf("SetUserRole: %v", err)
	}
	if err := s.DeleteRole(ctx, testActor, "auditor"); err != nil {
		t.Fatalf("DeleteRole after reassignment: %v", err)
	}
}
