const addr = Module.findExportByName("kernel32.dll", "OutputDebugStringA") ||
             Module.findExportByName("KERNELBASE.dll", "OutputDebugStringA");

if (addr) {
    Interceptor.attach(addr, {
        onEnter(args) {
            try {
                const s = args[0].readCString();  // ANSI 문자열 읽기
                if (s) console.log("[OutputDebugStringA]", s);
            } catch(e) {
                console.warn("Failed to read string:", e);
            }
        }
    });
    console.log("[+] Hooked OutputDebugStringA");
} else {
    console.warn("[!] OutputDebugStringA not found!");
}
