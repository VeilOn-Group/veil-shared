// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package redact

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"sync"
)

// Handler is a slog.Handler that scrubs every record before delegating.
// It cannot be configured off: construct loggers with NewLogger.
type Handler struct {
	next slog.Handler
	s    *Scrubber
}

// NewHandler wraps next.
func NewHandler(next slog.Handler, s *Scrubber) *Handler {
	if s == nil {
		s = Default
	}
	return &Handler{next: next, s: s}
}

// NewLogger returns a JSON logger to w whose records are always scrubbed.
// ReplaceAttr also drops the source location's full path (it may contain
// home-directory user names on clients).
func NewLogger(w io.Writer, level slog.Leveler, s *Scrubber) *slog.Logger {
	base := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(NewHandler(base, s))
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, h.s.String(r.Message), 0)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = h.attr(a)
	}
	return &Handler{next: h.next.WithAttrs(clean), s: h.s}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name), s: h.s}
}

func (h *Handler) attr(a slog.Attr) slog.Attr {
	if SensitiveKey(a.Key) {
		return slog.String(a.Key, Redacted)
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.s.String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		out := make([]any, 0, len(g))
		for _, ga := range g {
			out = append(out, h.attr(ga))
		}
		return slog.Group(a.Key, out...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, h.s.String(err.Error()))
		}
		// Unknown structured values are stringified and scrubbed rather than
		// trusting their JSON encoding.
		return slog.String(a.Key, h.s.String(v.String()))
	default:
		return slog.Attr{Key: a.Key, Value: v}
	}
}

// Writer scrubs line-oriented output (e.g. sing-box stderr) before writing it
// to dst. Partial lines are buffered until newline or Close.
type Writer struct {
	mu  sync.Mutex
	dst io.Writer
	s   *Scrubber
	buf bytes.Buffer
}

// NewWriter returns a scrubbing writer.
func NewWriter(dst io.Writer, s *Scrubber) *Writer { return &Writer{dst: dst, s: s} }

// maxLine bounds memory if a producer never writes a newline.
const maxLine = 64 << 10

// Write implements io.Writer.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			if w.buf.Len() > maxLine {
				if err := w.emit(w.buf.String()); err != nil {
					return len(p), err
				}
				w.buf.Reset()
			}
			return len(p), nil
		}
		line := string(w.buf.Next(i + 1))
		if err := w.emit(line[:len(line)-1]); err != nil {
			return len(p), err
		}
	}
}

// Close flushes a trailing partial line.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() == 0 {
		return nil
	}
	err := w.emit(w.buf.String())
	w.buf.Reset()
	return err
}

func (w *Writer) emit(line string) error {
	_, err := io.WriteString(w.dst, w.s.String(line)+"\n")
	return err
}

// Lines scrubs every line of r into w (helper for tools).
func Lines(r io.Reader, w io.Writer, s *Scrubber) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		if _, err := io.WriteString(w, s.String(sc.Text())+"\n"); err != nil {
			return err
		}
	}
	return sc.Err()
}
