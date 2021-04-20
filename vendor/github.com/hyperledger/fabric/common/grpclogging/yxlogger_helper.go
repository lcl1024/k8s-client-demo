package grpclogging

import (
	fabric_logs "github.com/hyperledger/fabric/logs"
	"go.uber.org/zap/zapcore"
	"sync"
)

/*
@Time : 2019-07-12 11:11
@Author : jilg
@File : yxlogger_helper
@Description:
*/
// 【日志转储】 定义一个日志函数map，在调用不同级别的log时调用对应的接口
var logFormatFuncMap = map[zapcore.Level]func(format string, fmtArgs ...interface{}){}
var once sync.Once

func InitMap(yxLogger *fabric_logs.FabricLogger) {

	logFormatFuncMap[zapcore.DebugLevel] = yxLogger.Debugf
	logFormatFuncMap[zapcore.InfoLevel] = yxLogger.Infof
	logFormatFuncMap[zapcore.WarnLevel] = yxLogger.Warningf
	logFormatFuncMap[zapcore.ErrorLevel] = yxLogger.Errorf
	logFormatFuncMap[zapcore.PanicLevel] = yxLogger.Alertf
	logFormatFuncMap[zapcore.FatalLevel] = yxLogger.Emergencyf
	logFormatFuncMap[zapcore.DPanicLevel] = yxLogger.Alertf

}

// 【日志转储】返回云象log接口,如果不存在该日志级别的则打印为warn日志
func yxLogger(yxLogger *fabric_logs.FabricLogger, lvl zapcore.Level) func(string, ...interface{}) {
	once.Do(func() {
		InitMap(yxLogger)
	})
	if _, ok := logFormatFuncMap[lvl]; ok {
		return logFormatFuncMap[lvl]
	} else {
		return logFormatFuncMap[zapcore.WarnLevel]
	}
}
