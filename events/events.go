package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// EventType represents the type of event
type EventType string

const (
	// User events
	EventUserCreated EventType = "user.created"
	EventUserUpdated EventType = "user.updated"
	EventUserDeleted EventType = "user.deleted"
	
	// Profile events
	EventProfileCreated EventType = "profile.created"
	EventProfileUpdated EventType = "profile.updated"
	EventProfileDeleted EventType = "profile.deleted"
	
	// Host events
	EventHostCreated EventType = "host.created"
	EventHostUpdated EventType = "host.updated"
	EventHostDeleted EventType = "host.deleted"
)

// Event represents a domain event
type Event struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Timestamp   time.Time              `json:"timestamp"`
	ServiceName string                 `json:"service_name"`
	UserID      string                 `json:"user_id,omitempty"`
	Data        map[string]interface{} `json:"data"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
}

// EventPublisher publishes events to other services
type EventPublisher interface {
	Publish(ctx context.Context, event *Event) error
	PublishBatch(ctx context.Context, events []*Event) error
}

// RedisEventPublisher publishes events using Redis Pub/Sub
type RedisEventPublisher struct {
	client      *redis.Client
	serviceName string
	tracer      trace.Tracer
}

// NewRedisEventPublisher creates a new Redis event publisher
func NewRedisEventPublisher(client *redis.Client, serviceName string) *RedisEventPublisher {
	return &RedisEventPublisher{
		client:      client,
		serviceName: serviceName,
		tracer:      otel.Tracer("event-publisher"),
	}
}

// Publish publishes a single event
func (p *RedisEventPublisher) Publish(ctx context.Context, event *Event) error {
	ctx, span := p.tracer.Start(ctx, "events.publish")
	defer span.End()

	span.SetAttributes(
		attribute.String("event.type", string(event.Type)),
		attribute.String("event.id", event.ID),
	)

	// Set service name if not already set
	if event.ServiceName == "" {
		event.ServiceName = p.serviceName
	}

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Serialize event
	data, err := json.Marshal(event)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish to Redis channel
	channel := fmt.Sprintf("events:%s", event.Type)
	if err := p.client.Publish(ctx, channel, data).Err(); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	// Also publish to a global events channel for monitoring
	if err := p.client.Publish(ctx, "events:all", data).Err(); err != nil {
		span.RecordError(err)
		// Don't fail the operation if this fails
	}

	return nil
}

// PublishBatch publishes multiple events
func (p *RedisEventPublisher) PublishBatch(ctx context.Context, events []*Event) error {
	ctx, span := p.tracer.Start(ctx, "events.publish_batch")
	defer span.End()

	span.SetAttributes(attribute.Int("event.count", len(events)))

	pipe := p.client.Pipeline()

	for _, event := range events {
		// Set service name if not already set
		if event.ServiceName == "" {
			event.ServiceName = p.serviceName
		}

		// Set timestamp if not already set
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}

		// Serialize event
		data, err := json.Marshal(event)
		if err != nil {
			span.RecordError(err)
			return fmt.Errorf("failed to marshal event: %w", err)
		}

		// Add to pipeline
		channel := fmt.Sprintf("events:%s", event.Type)
		pipe.Publish(ctx, channel, data)
		pipe.Publish(ctx, "events:all", data)
	}

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to publish events: %w", err)
	}

	return nil
}

// EventSubscriber subscribes to events from other services
type EventSubscriber interface {
	Subscribe(ctx context.Context, eventTypes []EventType, handler EventHandler) error
	Close() error
}

// EventHandler handles received events
type EventHandler func(ctx context.Context, event *Event) error

// RedisEventSubscriber subscribes to events using Redis Pub/Sub
type RedisEventSubscriber struct {
	client      *redis.Client
	serviceName string
	tracer      trace.Tracer
	pubsub      *redis.PubSub
}

// NewRedisEventSubscriber creates a new Redis event subscriber
func NewRedisEventSubscriber(client *redis.Client, serviceName string) *RedisEventSubscriber {
	return &RedisEventSubscriber{
		client:      client,
		serviceName: serviceName,
		tracer:      otel.Tracer("event-subscriber"),
	}
}

// Subscribe subscribes to specific event types
func (s *RedisEventSubscriber) Subscribe(ctx context.Context, eventTypes []EventType, handler EventHandler) error {
	channels := make([]string, len(eventTypes))
	for i, et := range eventTypes {
		channels[i] = fmt.Sprintf("events:%s", et)
	}

	// Subscribe to channels
	s.pubsub = s.client.Subscribe(ctx, channels...)

	// Wait for confirmation
	if _, err := s.pubsub.Receive(ctx); err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Start listening in a goroutine
	go s.listen(ctx, handler)

	return nil
}

// listen listens for incoming events
func (s *RedisEventSubscriber) listen(ctx context.Context, handler EventHandler) {
	ch := s.pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			s.handleMessage(ctx, msg, handler)
		}
	}
}

// handleMessage handles a received message
func (s *RedisEventSubscriber) handleMessage(ctx context.Context, msg *redis.Message, handler EventHandler) {
	ctx, span := s.tracer.Start(ctx, "events.handle_message")
	defer span.End()

	// Deserialize event
	var event Event
	if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
		span.RecordError(err)
		return
	}

	span.SetAttributes(
		attribute.String("event.type", string(event.Type)),
		attribute.String("event.id", event.ID),
		attribute.String("event.service", event.ServiceName),
	)

	// Call handler
	if err := handler(ctx, &event); err != nil {
		span.RecordError(err)
	}
}

// Close closes the subscription
func (s *RedisEventSubscriber) Close() error {
	if s.pubsub != nil {
		return s.pubsub.Close()
	}
	return nil
}

// Helper function to create an event
func NewEvent(eventType EventType, userID string, data map[string]interface{}) *Event {
	return &Event{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		UserID:    userID,
		Data:      data,
		Metadata:  make(map[string]string),
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

func randomString(length int) string {
	// Simple random string generator for event IDs
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = chars[time.Now().UnixNano()%int64(len(chars))]
	}
	return string(result)
}
