package api

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// FileMailer appends recovery messages to a file. It is a development
// stand-in for an SMTP/SES connector; the interface is what matters: the raw
// token never enters the database, so a database dump cannot be used to take
// over an account through the recovery path.
type FileMailer struct {
	Path string
	mu   sync.Mutex
}

// NewFileMailer returns a mailer writing to path.
func NewFileMailer(path string) *FileMailer { return &FileMailer{Path: path} }

// SendRecovery implements Mailer.
func (m *FileMailer) SendRecovery(to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.OpenFile(m.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s to=%s token=%s\n",
		time.Now().UTC().Format(time.RFC3339), to, token)
	return err
}
