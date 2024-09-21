package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"astuart.co/edgeos-rest/pkg/edgeos"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/jacobalberty/cs-edgeos-bouncer/internal/config"
	"github.com/jacobalberty/cs-edgeos-bouncer/pkg/xedgeos"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	cfg, err := config.GetConfig()
	if err != nil {
		return err
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         cfg.CSApi.Key,
		APIUrl:         cfg.CSApi.Url,
		TickerInterval: "20s",
	}

	if err := bouncer.Init(); err != nil {
		return err
	}

	eg, gctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		bouncer.Run(gctx)
		cancel()

		return nil
	})

	eg.Go(func() error {
		erClient, err := edgeos.NewClient(cfg.ERApi.Url, cfg.ERApi.User, cfg.ERApi.Pass)
		if err != nil {
			return err
		}
		if err = erClient.Login(); err != nil {
			return err
		}
		r, err := erClient.Get()
		if err != nil {
			return err
		}
		ag := xedgeos.NewAddressGroups(r)
		group, err := ag.GetGroup(cfg.ERApi.Group)
		if err != nil {
			return err
		}

		var hasChanges bool

	outer:
		for {
			select {
			case <-gctx.Done():
				break outer
			case decision := <-bouncer.Stream:
				for _, d := range decision.New {
					if group.Add(*d.Value) {
						hasChanges = true
						fmt.Printf("added %s to group\n", *d.Value)
					}
				}
				for _, d := range decision.Deleted {
					if group.Remove(*d.Value) {
						hasChanges = true
						fmt.Printf("removed %s from group\n", *d.Value)
					}
				}
			case <-time.Tick(5 * time.Second):
				if hasChanges {
					fmt.Println("updating group")
					hasChanges = false

					// TODO: implement set update and write the new address group
					// see https://github.com/Matthew1471/EdgeOS-API/blob/f79f4ab682a31d9c2418db20f30d11727edf7e21/Documentation/REST%20API/General%20-%20Configuration%20Settings%20Set.adoc

				}

			}
		}

		return nil
	})

	return eg.Wait()
}
