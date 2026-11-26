import DiemWeb
import JavaScriptEventLoop

// The standalone runtime exports DiemWeb's `@JS` API and nothing else.
JavaScriptEventLoop.installGlobalExecutor()
