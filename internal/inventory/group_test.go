package inventory

import (
	"reflect"
	"testing"

	"asi/internal/probe"
)

func httpService(port int, title, favicon string, techs ...Technology) ExportService {
	return ExportService{Port: port, Protocol: "tcp", Status: StatusActive,
		HTTP: &probe.HTTP{Title: title, FaviconSHA256: favicon}, Technologies: techs}
}

var (
	nginx = Technology{Name: "nginx", Version: "1.27"}
	php   = Technology{Name: "PHP", Version: "8.3"}
)

// REQ-INVENTORY-013
func TestGroupServices(t *testing.T) {
	hosts := []ExportHost{
		{Address: "10.0.0.10", Services: []ExportService{
			httpService(443, "Login", "aa", nginx, php),
			{Port: 22, Protocol: "tcp", Service: "ssh", Technologies: []Technology{nginx, php}},
		}},
		{Address: "10.0.0.2", Services: []ExportService{
			httpService(80, "Login", "aa", php, nginx, php),
			httpService(8080, "Login", "bb", nginx, php),
		}},
		{Address: "10.0.0.3", Services: []ExportService{
			httpService(443, "Login", "aa", php, nginx),
			httpService(80, "Other", "aa", nginx, php),
			httpService(81, "Login", "aa", nginx),
		}},
	}
	got := GroupServices(hosts)
	want := []ServiceGroup{
		{Key: ServiceGroupKey{Technologies: []string{"PHP 8.3", "nginx 1.27"}, Title: "Login", FaviconSHA256: "aa"}, Count: 3,
			Members: []ServiceGroupMember{{"10.0.0.2", 80, "tcp"}, {"10.0.0.3", 443, "tcp"}, {"10.0.0.10", 443, "tcp"}}},
		{Key: ServiceGroupKey{Technologies: []string{"PHP 8.3", "nginx 1.27"}, Title: "Login", FaviconSHA256: "bb"}, Count: 1,
			Members: []ServiceGroupMember{{"10.0.0.2", 8080, "tcp"}}},
		{Key: ServiceGroupKey{Technologies: []string{"PHP 8.3", "nginx 1.27"}, Title: "Other", FaviconSHA256: "aa"}, Count: 1,
			Members: []ServiceGroupMember{{"10.0.0.3", 80, "tcp"}}},
		{Key: ServiceGroupKey{Technologies: []string{"nginx 1.27"}, Title: "Login", FaviconSHA256: "aa"}, Count: 1,
			Members: []ServiceGroupMember{{"10.0.0.3", 81, "tcp"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GroupServices =\n%+v\nwant\n%+v", got, want)
	}
	reversed := []ExportHost{hosts[2], hosts[1], hosts[0]}
	for i := 0; i < 5; i++ {
		if again := GroupServices(reversed); !reflect.DeepEqual(again, want) {
			t.Fatalf("order depends on input: %+v", again)
		}
	}
	if g := GroupServices(nil); len(g) != 0 {
		t.Errorf("GroupServices(nil) = %+v", g)
	}
	noHTTP := []ExportHost{{Address: "10.0.0.1", Services: []ExportService{{Port: 22, Protocol: "tcp"}}}}
	if g := GroupServices(noHTTP); len(g) != 0 {
		t.Errorf("services without HTTP formed groups: %+v", g)
	}
}
