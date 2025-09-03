const addr = Module.findExportByName("kernel32.dll", "OutputDebugStringA");
if (addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      console.log("OutputDebugStringA called with:", args[0].readCString());
    }
  });
} else {
  console.warn("OutputDebugStringA not found");
}
