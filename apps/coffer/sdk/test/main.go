// Test runner for coffer.go; see scripts/sdk-matrix.ts.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"cofferdemo/coffer"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	ctx := context.Background()
	lang := os.Args[1]
	c, err := coffer.FromEnv()
	must(err)
	version, err := c.WriteSecret(ctx, "FROM_"+lang, "hello from "+lang+" ünï ✓ \"q\"\n<&>")
	must(err)
	got, _, err := c.GetSecret(ctx, "FROM_"+lang)
	must(err)
	_, found, err := c.GetSecret(ctx, "NOPE_MISSING")
	must(err)
	_, err = c.WriteSecret(ctx, "TMP_"+lang, "x")
	must(err)
	d1, err := c.DeleteSecret(ctx, "TMP_"+lang)
	must(err)
	d2, err := c.DeleteSecret(ctx, "TMP_"+lang)
	must(err)
	all, err := c.ListAllSecrets(ctx)
	must(err)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "got": got, "missingFound": found, "deletedOnce": d1, "deletedTwice": d2, "all": all}))
}
