package daemon

import (
	"log/slog"
	"time"
)

// SleepWatcher monitors for system sleep/wake events
type SleepWatcher struct {
	onWake   func()
	ticker   *time.Ticker
	lastTick time.Time
	done     chan struct{}
}

// NewSleepWatcher creates a new sleep watcher
func NewSleepWatcher(onWake func()) *SleepWatcher {
	return &SleepWatcher{
		onWake: onWake,
		done:   make(chan struct{}),
	}
}

// Start begins monitoring for sleep/wake events
func (w *SleepWatcher) Start() {
	w.ticker = time.NewTicker(1 * time.Second)
	w.lastTick = time.Now()

	go func() {
		for {
			select {
			case <-w.done:
				return
			case now := <-w.ticker.C:
				gap := now.Sub(w.lastTick)

				// If more than 5 seconds since last tick, system likely slept
				if gap > 5*time.Second {
					slog.Info("detected system wake", "gap", gap)
					if w.onWake != nil {
						w.onWake()
					}
				}

				w.lastTick = now
			}
		}
	}()
}

// Stop stops monitoring
func (w *SleepWatcher) Stop() {
	if w.ticker != nil {
		w.ticker.Stop()
	}
	close(w.done)
}
