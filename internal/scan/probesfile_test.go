package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"asi/internal/inventory"
	"asi/internal/scan"
	"asi/internal/scan/nmap"
	"asi/internal/scan/scantest"
)

const fakeNmapScript = `#!/bin/sh
prev=
sn=
hosts=
for a in "$@"; do
	[ "$prev" = --versiondb ] && printf '%s\n' "$a" >> "$LOG"
	[ "$a" = -sn ] && sn=1
	case "$a" in
	*.*.*.*) hosts="$hosts $a" ;;
	esac
	prev=$a
done
echo '<?xml version="1.0" encoding="UTF-8"?>'
echo '<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">'
for h in $hosts; do
	echo "<host><status state=\"up\" reason=\"syn-ack\"/><address addr=\"$h\" addrtype=\"ipv4\"/><hostnames></hostnames>"
	[ -z "$sn" ] && echo '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" method="probed" conf="10"/></port></ports>'
	echo '</host>'
done
echo '</nmaprun>'
`

func TestLightProbesFileCreatedOncePerRun(t *testing.T) {
	root := t.TempDir()
	share := filepath.Join(root, "share")
	tmp := filepath.Join(root, "tmp")
	for _, d := range []string{share, tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(share, "nmap-service-probes"), []byte("Probe TCP NULL q||\nsoftmatch http m|^HTTP/|\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "nmap")
	if err := os.WriteFile(bin, []byte(fakeNmapScript), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "versiondb.log")
	t.Setenv("NMAPDIR", share)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("LOG", log)

	tr := &scantest.Transport{}
	st := &scantest.Store{}
	settings := inventory.RunSettings{Targets: []string{"10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4"}, Ports: []int{22}, MaxRate: 1000, Workers: 1, GroupSize: 1}
	sc := &scan.Scanner{Store: st, Runner: nmap.ExecRunner{Path: bin}, Transport: tr.For, Clock: scantest.NewClock(time.Unix(0, 0))}
	if err := sc.Run(context.Background(), testRun(settings)); err != nil {
		t.Fatal(err)
	}
	if n := len(st.Hosts()); n != 4 {
		t.Fatalf("hosts = %d, want 4", n)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	paths := strings.Fields(string(raw))
	if len(paths) < 4 {
		t.Fatalf("service detections with --versiondb = %d, want one per group (4)", len(paths))
	}
	slices.Sort(paths)
	if distinct := slices.Compact(paths); len(distinct) != 1 {
		t.Errorf("trimmed probe files written = %d for a %d-group run, want 1: %q", len(distinct), 4, distinct)
	}
	left, err := filepath.Glob(filepath.Join(tmp, "*nmap-service-probes*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("trimmed probe files left behind after the run: %q", left)
	}
}
