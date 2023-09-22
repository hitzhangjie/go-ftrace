package uprobe

import (
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func Test_NewFetchArg(t *testing.T) {

	str := "s.name=(*0(%ax)):c64"
	vals := strings.Split(str, "=")
	arg, err := newFetchArg(vals[0], vals[1])
	require.Nil(t, err)

	spew.Dump(arg)
}

func Test_NewFetchArg2(t *testing.T) {

	str := "s.name=(+16(%ax)):c64"
	vals := strings.Split(str, "=")
	arg, err := newFetchArg(vals[0], vals[1])
	require.Nil(t, err)

	spew.Dump(arg)
}
