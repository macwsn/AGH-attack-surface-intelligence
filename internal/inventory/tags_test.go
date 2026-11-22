package inventory

import (
	"reflect"
	"testing"
)

func TestCleanTagsKeepsSpacesAndSplitsListSeparators(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want []string
	}{
		{[]string{"crown jewel", "dmz"}, []string{"crown jewel", "dmz"}},
		{[]string{" crown jewel ", "dmz", "dmz"}, []string{"crown jewel", "dmz"}},
		{[]string{"a,b", "c;d", "e\nf"}, []string{"a", "b", "c", "d", "e", "f"}},
		{[]string{"", " , ;"}, []string{}},
		{nil, []string{}},
	} {
		if got := cleanTags(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("cleanTags(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
