package main

import (
	"context"
	"fmt"
	"log"
	"net"
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
		group.Reset()

		var hasChanges bool

	outer:
		for {
			select {
			case <-gctx.Done():
				break outer
			case decision := <-bouncer.Stream:
				for _, d := range decision.New {
					ip := net.ParseIP(*d.Value)
					if ip != nil &&
						ip.To4() != nil &&
						*d.Type == "ban" &&
						group.Add(*d.Value) {
						hasChanges = true
					}
				}
				for _, d := range decision.Deleted {
					ip := net.ParseIP(*d.Value)
					if ip != nil &&
						ip.To4() != nil && *d.Type == "ban" && group.Remove(*d.Value) {
						hasChanges = true
					}
				}
			case <-time.Tick(5 * time.Second):
				if hasChanges {
					log.Println("updating group")
					hasChanges = false

					setData, err := ag.GetSetData(group)
					if err != nil {
						return err
					}
					delData, err := ag.GetDeleteData(group)
					if err != nil {
						return err
					}
					log.Printf("old address count %v\n", len((*ag)[group.Name].Address))
					log.Printf("new address count %v\n", len(group.Address))
					for _, curDel := range delData {
						_, err = erClient.Delete(curDel)
						if err != nil {
							return err
						}
					}
					for _, curSet := range setData {
						_, err := erClient.Set(curSet)
						if err != nil {
							return err
						}
					}

					log.Println("group updated")
					r, err := erClient.Get()
					if err != nil {
						return err
					}
					ag, err := xedgeos.NewAddressGroups(r)
					if err != nil {
						return err
					}
					log.Printf("Stored address count %v\n", len((*ag)[group.Name].Address))
					os.Exit(0)
				}

			}
		}

		return nil
	})

	return eg.Wait()
}
