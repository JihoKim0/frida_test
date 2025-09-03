'use strict';

function safeReadAnsi(ptr, len) {
    if(!ptr || ptr.isNull() || len <= 0) return null;
    try { return ptr.readAnsiString(len); } catch(e){ return null; }
}

function safeReadUtf16(ptr, len) {
    if(!ptr || ptr.isNull() || len <= 0) return null;
    try { return ptr.readUtf16String(len); } catch(e){ return null; }
}

function dump(tag, str){
    if(str) console.log(`[${tag}] ${str.replace(/\r/g,'\\r').replace(/\n/g,'\\n')}`);
}

function hookFunction(ptr, name, callback){
    if(!ptr) return;
    Interceptor.attach(ptr, { onEnter: callback });
    console.log(`[+] Hooked ${name} @ ${ptr}`);
}

// 안전 attach, 없으면 심볼 스캔 후 attach
function safeAttach(moduleName, funcName, isAnsi, argIndex){
    argIndex = argIndex || 0;
    let addr = null;
    try { addr = Module.findExportByName(moduleName, funcName); } catch(e){}
    if(addr){
        hookFunction(addr, funcName, function(args){
            try {
                const s = isAnsi? safeReadAnsi(args[argIndex]): safeReadUtf16(args[argIndex]);
                if(s) dump(funcName, s);
            } catch(e){}
        });
    } else {
        try {
            const syms = Module.findSymbols(moduleName);
            syms.forEach(s=>{
                if(s.name.indexOf(funcName) >= 0){
                    hookFunction(s.address, funcName, function(args){
                        try {
                            const s2 = isAnsi? safeReadAnsi(args[argIndex]): safeReadUtf16(args[argIndex]);
                            if(s2) dump(funcName, s2);
                        } catch(e){}
                    });
                }
            });
        } catch(e){}
    }
}

// ---------------- Module 탐색 및 후킹 -----------------
setImmediate(function(){
    console.log("[*] Enumerating loaded modules...");
    Process.enumerateModules().forEach(m=>{
        console.log(`- ${m.name} @ ${m.base}`);
    });

    const kernel = ["kernel32.dll","KERNELBASE.dll"];
    const user = ["user32.dll"];
    const ws = ["ws2_32.dll"];

    console.log("[*] Attempting hooks...");

    // Windows API 후킹
    kernel.forEach(m=>{
        safeAttach(m, "OutputDebugStringA", true);
        safeAttach(m, "OutputDebugStringW", false);
        safeAttach(m, "WriteConsoleA", true, 1);
        safeAttach(m, "WriteConsoleW", false, 1);
        safeAttach(m, "WriteFile", true, 1);
    });

    user.forEach(m=>{
        safeAttach(m, "MessageBoxA", true, 1);
        safeAttach(m, "MessageBoxW", false, 1);
        safeAttach(m, "SendMessageA", true, 2);
        safeAttach(m, "SendMessageW", false, 2);
    });

    ws.forEach(m=>{
        safeAttach(m, "send", true, 1);
        safeAttach(m, "recv", true, 1);
    });

    console.log("[*] Hook setup attempted on standard APIs.");
});
