package biscuittest

import (
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go"
	"github.com/biscuit-auth/biscuit-go/parser"
	"github.com/stretchr/testify/require"
)

type interval struct {
	n string
	d time.Duration
}
type timer struct {
	intervals   []*interval
	curIntStart time.Time
}

func (tr *timer) Reset() {
	tr.intervals = []*interval{}
}

func (tr *timer) NewInterval(name string) {
	tr.Stop()
	tr.intervals = append(tr.intervals, &interval{n: name, d: 0})
	tr.curIntStart = time.Now()
}

func (tr *timer) Stop() {
	c := len(tr.intervals) - 1
	if c < 0 {
		return
	}
	i := tr.intervals[c]
	i.d += time.Since(tr.curIntStart)
}

func (tr *timer) Continue() {
	tr.curIntStart = time.Now()
}

func (tr *timer) Print(t *testing.T) {
	for i := range tr.intervals {
		t.Logf("%s took %fs\n", tr.intervals[i].n, tr.intervals[i].d.Seconds())
	}
}

func TestFacts22_DefaultSymbols(t *testing.T) {
	for _, v := range versions {
		sw := &timer{}
		t.Run(v, func(t *testing.T) {
			token := loadSampleToken(t, v, "test22_default_symbols.bc")

			b, err := biscuit.Unmarshal(token)
			require.NoError(t, err)

			t.Log(b.String())

			v, err := b.Authorizer(loadRootPublicKey(t, v))
			require.NoError(t, err)

			sw.NewInterval("FromStringCheck")
			check1, err := parser.FromStringCheck(`check if 
			read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), 
			user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19),
			domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27)`)
			require.NoError(t, err)
			sw.NewInterval("AddCheck")
			v.AddCheck(check1)

			// separate in two checks because the parser gest slow at more than 20 facts
			/*			check2, err := parser.FromStringCheck(`check if
						ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22),
						cluster(23), node(24), hostname(25), nonce(26), query(27)`)
						require.NoError(t, err)
						v.AddCheck(check2)
			*/
			sw.NewInterval("AddPolicy")
			v.AddPolicy(biscuit.DefaultAllowPolicy)

			sw.NewInterval("Authorize")
			require.NoError(t, v.Authorize())
			sw.Stop()
			sw.Print(t)
		})
	}
}
