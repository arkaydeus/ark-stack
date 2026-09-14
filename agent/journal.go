package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type journalEntry struct {
	ID     string    `json:"id"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Status string    `json:"status"`
	At     time.Time `json:"at"`
	Note   string    `json:"note"`
}

type journal struct {
	mu   sync.Mutex
	path string
}

func (j *journal) append(entry journalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entry.At = time.Now().UTC()
	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(entry)
}
