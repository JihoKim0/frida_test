'use strict';

// ----------------- 안전 문자열 읽기 -----------------
function safeReadAnsi(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readCString(); } catch(e) { return null; }
}

function safeReadUtf16(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { return ptr.readUtf16String(); } catch(e) { return null; }
}

// ----------------- 출력 헬퍼 -----------------
function dump(tag, str) {
    if (str) console.log(`[${tag}] ${str.replace(/\r/g,"\\r").replace(/\n/g,"\\n")}`);
}

// ----------------- 안전 attach -----------------
function safeAttach(moduleNames, funcName, onEnterCallback) {
    let addr = null;
    for (let m of moduleNames) {
        try {
            addr = Module.findExportByName(m, funcName);
            if (addr) break;
        } catch(e) {}
    }
    if (!addr) {
        console.warn(`[!] ${funcName} not found in ${moduleNames.join(", ")}`);
        return;
    }
    Interceptor.attach(addr, { onEnter: onEnterCallback });
    console.log(`[+] Hooked ${funcName} @ ${addr}`);
}

// ----------------- 후킹 -----------------
setImmediate(function() {
    // 모듈 초기화
    Module.ensureInitialized("kernel32.dll");
    Module.ensureInitialized("KERNELBASE.dll");
    Module.ensureInitialized("user32.dll");

    // OutputDebugString
    safeAttach(["kernel32.dll","KERNELBASE.dll"], "OutputDebugStringA", function(args) {
        dump("OutputDebugStringA", safeReadAnsi(args[0]));
    });
    safeAttach(["kernel32.dll","KERNELBASE.dll"], "OutputDebugStringW", function(args) {
        dump("OutputDebugStringW", safeReadUtf16(args[0]));
    });

    // MessageBox
    safeAttach(["user32.dll"], "MessageBoxA", function(args) {
        dump("MessageBoxA [Text]", safeReadAnsi(args[1]));
        dump("MessageBoxA [Caption]", safeReadAnsi(args[2]));
    });
    safeAttach(["user32.dll"], "MessageBoxW", function(args) {
        dump("MessageBoxW [Text]", safeReadUtf16(args[1]));
        dump("MessageBoxW [Caption]", safeReadUtf16(args[2]));
    });

    // WriteConsole
    safeAttach(["kernel32.dll","KERNELBASE.dll"], "WriteConsoleA", function(args) {
        const buf = args[1];
        const len = args[2] ? args[2].toInt32() : 0;
        if (buf && len>0) {
            try { dump("WriteConsoleA", buf.readAnsiString(len)); } catch(e) {}
        }
    });
    safeAttach(["kernel32.dll","KERNELBASE.dll"], "WriteConsoleW", function(args) {
        const buf = args[1];
        const len = args[2] ? args[2].toInt32() : 0;
        if (buf && len>0) {
            try { dump("WriteConsoleW", buf.readUtf16String(len)); } catch(e) {}
        }
    });

    console.log("[*] All hooks installed safely");
});
