package logger

import (
	"io"
)

type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelError
	LogLevelWarning
	LogLevelInfo
	LogLevelVerbose
	LogLevelDebug
)

type Logger interface {
	Debug(format string, args ...interface{})
	Verbose(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warning(format string, args ...interface{})
	Error(format string, args ...interface{})
	Fatal(format string, args ...interface{})
	
	SetLevel(level LogLevel)
	SetPrefix(prefix string)
	SetOutput(w io.Writer)
}

func SetVerbose(verbose bool) {
	if verbose {
		GetLogger().SetLevel(LogLevelVerbose)
	} else {
		GetLogger().SetLevel(LogLevelInfo)
	}
}

func Debug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

func Verbose(format string, args ...interface{}) {
	GetLogger().Verbose(format, args...)
}

func Info(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

func Warning(format string, args ...interface{}) {
	GetLogger().Warning(format, args...)
}

func Error(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	GetLogger().Fatal(format, args...)
}