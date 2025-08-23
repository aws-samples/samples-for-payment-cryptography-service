package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type DefaultLogger struct {
	level  LogLevel
	prefix string
	output io.Writer
	mu     sync.Mutex
}

var defaultLogger *DefaultLogger
var once sync.Once

func GetLogger() Logger {
	once.Do(func() {
		defaultLogger = &DefaultLogger{
			level:  LogLevelInfo,
			output: os.Stdout,
		}
	})
	return defaultLogger
}

func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *DefaultLogger) SetPrefix(prefix string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
}

func (l *DefaultLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

func (l *DefaultLogger) log(level LogLevel, levelStr string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level > l.level {
		return
	}

	message := fmt.Sprintf(format, args...)

	if l.prefix != "" {
		message = l.prefix + " " + message
	}

	if levelStr != "" && (level == LogLevelDebug || level <= LogLevelWarning) {
		message = "[" + levelStr + "] " + message
	}

	fmt.Fprintln(l.output, message)
}

func (l *DefaultLogger) logWithTimestamp(level LogLevel, levelStr string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level > l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	if l.prefix != "" {
		message = l.prefix + " " + message
	}

	fullMessage := fmt.Sprintf("%s [%s] %s", timestamp, levelStr, message)
	fmt.Fprintln(l.output, fullMessage)
}

func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	l.log(LogLevelDebug, "DEBUG", format, args...)
}

func (l *DefaultLogger) Verbose(format string, args ...interface{}) {
	l.log(LogLevelVerbose, "", format, args...)
}

func (l *DefaultLogger) Info(format string, args ...interface{}) {
	l.log(LogLevelInfo, "", format, args...)
}

func (l *DefaultLogger) Warning(format string, args ...interface{}) {
	l.log(LogLevelWarning, "WARNING", format, args...)
}

func (l *DefaultLogger) Error(format string, args ...interface{}) {
	l.log(LogLevelError, "ERROR", format, args...)
}

func (l *DefaultLogger) Fatal(format string, args ...interface{}) {
	l.log(LogLevelError, "FATAL", format, args...)
	panic(fmt.Sprintf(format, args...))
}
