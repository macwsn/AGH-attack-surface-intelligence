package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"asi/internal/auth"
	"asi/internal/config"
	"asi/internal/store"
)

type userAction struct {
	verb string
	userCreateArgs
}

func parseUser(args []string) (userAction, error) {
	if len(args) == 0 {
		return userAction{}, errUsage
	}
	a := userAction{verb: args[0]}
	switch a.verb {
	case "create":
		c, err := parseUserCreate(args)
		return userAction{verb: a.verb, userCreateArgs: c}, err
	case "list":
		if len(args) > 1 {
			return userAction{}, errUsage
		}
		return a, nil
	case "set-role", "delete":
		fs := flag.NewFlagSet("user "+a.verb, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.StringVar(&a.username, "username", "", "")
		if a.verb == "set-role" {
			fs.StringVar(&a.role, "role", "", "")
		}
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 || a.username == "" || (a.verb == "set-role" && a.role == "") {
			return userAction{}, errUsage
		}
		return a, nil
	}
	return userAction{}, errUsage
}

func parseRole(args []string) error {
	if len(args) != 1 || args[0] != "list" {
		return errUsage
	}
	return nil
}

func runUser(ctx context.Context, cfg config.Config, a userAction, stdin io.Reader, stdout io.Writer) error {
	if a.verb == "create" {
		return userCreate(ctx, cfg, a.userCreateArgs, stdin, stdout)
	}
	return withAuth(ctx, cfg, func(svc *auth.Service) error {
		switch a.verb {
		case "list":
			users, err := svc.ListUsers(ctx)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "USERNAME\tROLE\tSTATUS\tCREATED")
			for _, u := range users {
				status := "enabled"
				if u.Disabled {
					status = "disabled"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Username, u.Role, status, u.CreatedAt.UTC().Format(time.RFC3339))
			}
			return tw.Flush()
		case "set-role":
			if err := svc.SetUserRole(ctx, cliActor, a.username, a.role); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "user %s now has role %s\n", a.username, a.role)
		case "delete":
			if err := svc.DeleteUser(ctx, cliActor, a.username); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "user %s deleted\n", a.username)
		}
		return nil
	})
}

func roleList(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	return withAuth(ctx, cfg, func(svc *auth.Service) error {
		roles, err := svc.ListRoles(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ROLE\tBUILTIN\tPERMISSIONS")
		for _, r := range roles {
			perms := make([]string, len(r.Permissions))
			for i, p := range r.Permissions {
				perms[i] = string(p)
			}
			fmt.Fprintf(tw, "%s\t%t\t%s\n", r.Name, r.Builtin, strings.Join(perms, ","))
		}
		return tw.Flush()
	})
}

func withAuth(ctx context.Context, cfg config.Config, fn func(*auth.Service) error) error {
	s, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(auth.NewService(s, auth.Config{}))
}
