// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/stretchr/testify/assert"
)

// A notification consumer can read a snapshot before receiving another event.
// Even if updates is full, the producer must not hold the corpus lock while
// waiting for that consumer. Exercise all notification-producing entry points.
func TestDirectedNotificationsReleaseCorpusLock(t *testing.T) {
	for _, capacity := range []int{0, 1} {
		for _, operation := range []string{"save", "save-directed", "gain", "restore"} {
			t.Run(fmt.Sprintf("%s/buffer=%d", operation, capacity), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				updates := make(chan NewItemEvent, capacity)
				c := NewDirectedCorpus(ctx, updates, testDirectedCoverage())
				if capacity != 0 {
					c.RestoreDirectedGainHistory([]uint64{999})
				}
				inp := directedTestInput(t, 1, signal.FromRaw([]uint64{500}, 3))
				sig := hash.String(inp.Prog.Serialize())
				witness := c.DirectedWitness([]uint64{10})
				writerDone := make(chan struct{})
				go func() {
					defer close(writerDone)
					switch operation {
					case "save":
						c.Save(inp)
					case "save-directed":
						c.SaveDirected(inp, []uint64{10}, witness, inp.Signal)
					case "gain":
						c.RecordDirectedGain("", []uint64{10})
					case "restore":
						c.RestoreDirectedGainHistory([]uint64{10})
					}
				}()
				snapshotDone := make(chan struct{})
				go func() {
					defer close(snapshotDone)
					for ctx.Err() == nil {
						if operation == "save" || operation == "save-directed" {
							if c.Item(sig) != nil {
								return
							}
						} else if slices.Contains(c.DirectedGainHistory(), uint64(10)) {
							return
						}
						runtime.Gosched()
					}
				}()
				select {
				case <-snapshotDone:
				case <-time.After(2 * time.Second):
					t.Error("snapshot blocked behind a producer waiting for the update consumer")
				}
				// No consumer drains updates in this test. Cancellation releases
				// the intentionally blocked notification without leaking goroutines.
				cancel()
				select {
				case <-writerDone:
				case <-time.After(2 * time.Second):
					t.Fatal("notification producer did not stop")
				}
				select {
				case <-snapshotDone:
				case <-time.After(2 * time.Second):
					t.Fatal("snapshot reader did not stop")
				}
				if operation == "save" || operation == "save-directed" {
					assert.NotNil(t, c.Item(sig))
				} else {
					assert.Contains(t, c.DirectedGainHistory(), uint64(10))
				}
			})
		}
	}
}
