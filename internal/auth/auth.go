package auth

import (
	"errors"
	"sync"
	"time"

	"asi/internal/store"
)

type Permission string

const (
	PermInventoryRead   Permission = "inventory.read"
	PermInventoryEdit   Permission = "inventory.edit"
	PermInventoryCreate Permission = "inventory.create"
	PermInventoryDelete Permission = "inventory.delete"
	PermScanRun         Permission = "scan.run"
	PermScanConfigure   Permission = "scan.configure"
	PermSignatureManage Permission = "signature.manage"
	PermExport          Permission = "export"
	PermImport          Permission = "import"
	PermUserManage      Permission = "user.manage"
	PermRoleManage      Permission = "role.manage"
)

var AllPermissions = []Permission{
	PermInventoryRead,
	PermInventoryEdit,
	PermInventoryCreate,
	PermInventoryDelete,
	PermScanRun,
	PermScanConfigure,
	PermSignatureManage,
	PermExport,
	PermImport,
	PermUserManage,
	PermRoleManage,
}

const (
	RoleAdmin    = "admin"
	RoleEditor   = "editor"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

var (
	ErrPasswordTooShort   = errors.New("password must be at least 12 characters")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrRateLimited        = errors.New("too many failed logins, try again later")
	ErrNoSession          = errors.New("no valid session")
	ErrUnknownUser        = errors.New("unknown user")
	ErrUserExists         = errors.New("user already exists")
	ErrUnknownRole        = errors.New("unknown role")
	ErrRoleExists         = errors.New("role already exists")
	ErrRoleInUse          = errors.New("role is assigned to a user")
	ErrBuiltinRole        = errors.New("built-in role cannot be changed")
	ErrUnknownPermission  = errors.New("unknown permission")
	ErrLastAdmin          = errors.New("the last admin cannot be deleted or demoted")
)

type User struct {
	Username  string
	Role      string
	CreatedAt time.Time
}

type Role struct {
	Name        string
	Builtin     bool
	Permissions []Permission
}

type Session struct {
	Token     string
	CSRFToken string
	Username  string
	CreatedAt time.Time
}

type Principal struct {
	Username    string
	Role        string
	Permissions []Permission
	CSRFToken   string
}

type Actor struct {
	Username string
	Addr     string
}

type Config struct {
	Now             func() time.Time
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	AccountLimit    int
	AddressLimit    int
	LimitWindow     time.Duration
}

const (
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultAbsoluteTimeout = 12 * time.Hour
	DefaultAccountLimit    = 5
	DefaultAddressLimit    = 20
	DefaultLimitWindow     = 15 * time.Minute
)

func (c Config) withDefaults() Config {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.AbsoluteTimeout <= 0 {
		c.AbsoluteTimeout = DefaultAbsoluteTimeout
	}
	if c.AccountLimit <= 0 {
		c.AccountLimit = DefaultAccountLimit
	}
	if c.AddressLimit <= 0 {
		c.AddressLimit = DefaultAddressLimit
	}
	if c.LimitWindow <= 0 {
		c.LimitWindow = DefaultLimitWindow
	}
	return c
}

type Service struct {
	store     *store.Store
	cfg       Config
	dummyHash string

	mu              sync.Mutex
	accountFailures map[string][]time.Time
	addressFailures map[string][]time.Time
}

func NewService(st *store.Store, cfg Config) *Service {
	return &Service{
		store:           st,
		cfg:             cfg.withDefaults(),
		dummyHash:       dummyPasswordHash(),
		accountFailures: make(map[string][]time.Time),
		addressFailures: make(map[string][]time.Time),
	}
}
