package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

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
		erClient, err := xedgeos.NewClient(cfg.ERApi.Url, cfg.ERApi.User, cfg.ERApi.Pass)
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
		ag, err := xedgeos.NewAddressGroups(r)
		if err != nil {
			return err
		}
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
					ag.UpdateGroup(cfg.ERApi.Group, group)
					hasChanges = false
					data := ag.GetUpdateData(cfg.ERApi.Group)

					if _, err := erClient.Set(data); err != nil {
						return err
					}
				}

			}
		}

		return nil
	})

	return eg.Wait()
}
