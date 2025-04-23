package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/joho/godotenv"
	"github.com/willdot/statusphere-go"
	"github.com/willdot/statusphere-go/database"
	"github.com/willdot/statusphere-go/oauth"
)

const (
	defaultServerAddr                = "wss://jetstream.atproto.tools/subscribe"
	httpClientTimeoutDuration        = time.Second * 5
	transportIdleConnTimeoutDuration = time.Second * 90
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatal("Error loading .env file")
		}
	}

	host := os.Getenv("HOST")
	if host == "" {
		slog.Error("missing HOST env variable")
		return
	}

	dbMountPath := os.Getenv("DATABASE_MOUNT_PATH")
	if dbMountPath == "" {
		slog.Error("DATABASE_MOUNT_PATH env not set")
		return
	}

	dbFilename := path.Join(dbMountPath, "database.db")
	db, err := database.New(dbFilename)
	if err != nil {
		slog.Error("create new database", "error", err)
		return
	}
	defer db.Close()

	httpClient := &http.Client{
		Timeout: httpClientTimeoutDuration,
		Transport: &http.Transport{
			IdleConnTimeout: transportIdleConnTimeoutDuration,
		},
	}

	oauthService, err := oauth.NewService(db, host, httpClient)
	if err != nil {
		slog.Error("creating new oauth service", "error", err)
		return
	}

	server, err := statusphere.NewServer(host, 8080, db, oauthService, httpClient)
	if err != nil {
		slog.Error("create new server", "error", err)
		return
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-signals
		cancel()
		_ = server.Stop(context.Background())
	}()

	go consumeLoop(ctx, db)

	server.Run()
}

func consumeLoop(ctx context.Context, db *database.DB) {
	jsServerAddr := os.Getenv("JS_SERVER_ADDR")
	if jsServerAddr == "" {
		jsServerAddr = defaultServerAddr
	}

	consumer := statusphere.NewConsumer(jsServerAddr, slog.Default(), db)

	err := retry.Do(func() error {
		err := consumer.Consume(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			slog.Error("consume loop", "error", err)
			return err
		}
		return nil
	}, retry.UntilSucceeded()) // retry indefinitly until context canceled
	slog.Error(err.Error())
	slog.Warn("exiting consume loop")
}
