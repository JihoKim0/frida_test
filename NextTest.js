setImmediate(function() {
    // 모듈 초기화 보장
    Module.ensureInitialized("kernel32.dll");
    Module.ensureInitialized("KERNELBASE.dll");

    const addr = Module.findExportByName("kernel32.dll", "OutputDebugStringA") ||
                 Module.findExportByName("KERNELBASE.dll", "OutputDebugStringA");

    if (!addr) {
        console.warn("[!] OutputDebugStringA not found!");
        return;
    }

    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const s = args[0].readCString();
                if (s) console.log("[OutputDebugStringA]", s);
            } catch (e) {
                console.warn("Failed to read string:", e);
            }
        }
    });

    console.log("[+] Hooked OutputDebugStringA safely");
});
