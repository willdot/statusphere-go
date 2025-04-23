package statusphere

import (
	"context"
	"encoding/json"

	"fmt"
	"log/slog"
	"time"

	"github.com/bluesky-social/jetstream/pkg/client"
	"github.com/bluesky-social/jetstream/pkg/client/schedulers/sequential"
	"github.com/bluesky-social/jetstream/pkg/models"
)

type consumer struct {
	cfg     *client.ClientConfig
	handler handler
	logger  *slog.Logger
}

func NewConsumer(jsAddr string, logger *slog.Logger, store HandlerStore) *consumer {
	cfg := client.DefaultClientConfig()
	if jsAddr != "" {
		cfg.WebsocketURL = jsAddr
	}
	cfg.WantedCollections = []string{
		"xyz.statusphere.status",
	}
	cfg.WantedDids = []string{}

	return &consumer{
		cfg:    cfg,
		logger: logger,
		handler: handler{
			store: store,
		},
	}
}

func (c *consumer) Consume(ctx context.Context) error {
	scheduler := sequential.NewScheduler("jetstream_localdev", c.logger, c.handler.HandleEvent)
	defer scheduler.Shutdown()

	client, err := client.NewClient(c.cfg, c.logger, scheduler)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	cursor := time.Now().Add(1 * -time.Minute).UnixMicro()

	if err := client.ConnectAndRead(ctx, &cursor); err != nil {
		return fmt.Errorf("connect and read: %w", err)
	}

	slog.Info("stopping consume")
	return nil
}

type HandlerStore interface {
	CreateStatus(status Status) error
}

type handler struct {
	store HandlerStore
}

func (h *handler) HandleEvent(ctx context.Context, event *models.Event) error {
	if event.Commit == nil {
		return nil
	}

	switch event.Commit.Operation {
	case models.CommitOperationCreate:
		return h.handleCreateEvent(ctx, event)
	default:
		return nil
	}
}

type StatusRecord struct {
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

func (h *handler) handleCreateEvent(_ context.Context, event *models.Event) error {
	var statusRecord StatusRecord
	if err := json.Unmarshal(event.Commit.Record, &statusRecord); err != nil {
		slog.Error("unmarshal record", "error", err)
		return nil
	}

	uri := fmt.Sprintf("at://%s/%s/%s", event.Did, event.Commit.Collection, event.Commit.RKey)

	status := Status{
		URI:       uri,
		Did:       event.Did,
		Status:    statusRecord.Status,
		CreatedAt: statusRecord.CreatedAt.UnixMilli(),
		IndexedAt: time.Now().UnixMilli(),
	}
	err := h.store.CreateStatus(status)
	if err != nil {
		slog.Error("failed to store status", "error", err)
	}

	return nil
}
