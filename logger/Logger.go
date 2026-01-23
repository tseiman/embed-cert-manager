package logger

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
)

type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

var currentLevel atomic.Int32

func SetLevel(l Level) { currentLevel.Store(int32(l)) }
func GetLevel() Level  { return Level(currentLevel.Load()) }
func enabled(l Level) bool { return GetLevel() >= l }

func levelTag(l Level) string {
	switch l {
	case LevelError:
		return "[ERROR]"
	case LevelWarn:
		return "[WARN ]"
	case LevelInfo:
		return "[INFO ]"
	default:
		return "[DEBUG]"
	}
}

func callerShort(depth int) string {
	// depth: 0=callerShort, 1=output, 2=Infof/..., 3=real caller
	_, file, line, ok := runtime.Caller(depth)
	if !ok {
		return "?:0"
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

func output(l Level, msg string) {
	if !enabled(l) {
		return
	}

	// Put level first, then file:line, then message.
	loc := callerShort(3)

	// Use log.Output so timestamp flags still apply; calldepth=2 points to output()
	// but we are *not* using log's caller formatting anymore.
	_ = log.Output(2, fmt.Sprintf("%s %s %s", levelTag(l), loc, msg))
}

// ---- Printf variants ----
func Errorf(format string, v ...any) { output(LevelError, fmt.Sprintf(format, v...)) }
func Warnf(format string, v ...any)  { output(LevelWarn,  fmt.Sprintf(format, v...)) }
func Infof(format string, v ...any)  { output(LevelInfo,  fmt.Sprintf(format, v...)) }
func Debugf(format string, v ...any) { output(LevelDebug, fmt.Sprintf(format, v...)) }

// ---- Println variants ----
func Errorln(v ...any) { output(LevelError, strings.TrimRight(fmt.Sprintln(v...), "\n")) }
func Warnln(v ...any)  { output(LevelWarn,  strings.TrimRight(fmt.Sprintln(v...), "\n")) }
func Infoln(v ...any)  { output(LevelInfo,  strings.TrimRight(fmt.Sprintln(v...), "\n")) }
func Debugln(v ...any) { output(LevelDebug, strings.TrimRight(fmt.Sprintln(v...), "\n")) }




