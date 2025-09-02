function hookOutputDebug() {
  ["OutputDebugStringA", "OutputDebugStringW"].forEach(fn => {
    const addr = Module.findExportByName("kernel32.dll", fn) ||
                 Module.findExportByName("KERNELBASE.dll", fn);
    if (!addr) {
      console.warn(`[!] ${fn} not found`);
      return;
    }
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          const s = fn.endsWith("W") ? safeReadUtf16(args[0]) : safeReadAnsi(args[0]);
          if (s) console.log(`[${fn}] ${s}`);
        } catch (e) { console.warn("err:", e); }
      }
    });
    console.log(`[+] Hooked ${fn}`);
  });
}

hookOutputDebug();
