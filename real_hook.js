'use strict';

// 안전 문자열 읽기
function safeReadAnsi(ptr, len){
    if(!ptr || ptr.isNull() || len<=0) return null;
    try { return ptr.readAnsiString(len); } catch(e){ return null; }
}
function safeReadUtf16(ptr, len){
    if(!ptr || ptr.isNull() || len<=0) return null;
    try { return ptr.readUtf16String(len); } catch(e){ return null; }
}
function dump(tag,str){
    if(str) console.log(`[${tag}] ${str.replace(/\r/g,'\\r').replace(/\n/g,'\\n')}`);
}

// 범용 NativePointer 후킹
function hookFunction(ptr, name, onEnter){
    if(!ptr) return;
    Interceptor.attach(ptr, { onEnter: onEnter });
    console.log(`[+] Hooked ${name} @ ${ptr}`);
}

// 문자열 추적용 Scan + 후킹
function scanAndHook(moduleName, pattern, name, onEnter){
    try {
        const m = Module.findModuleByName(moduleName);
        if(!m) return;
        Memory.scan(m.base, m.size, pattern, {
            onMatch: function(addr, size){
                hookFunction(addr, name, onEnter);
            },
            onComplete: function(){}
        });
    } catch(e){}
}

// ----------------- 후킹 함수 -----------------
setImmediate(function(){
    const kernel = ["kernel32.dll","KERNELBASE.dll"];
    const user = ["user32.dll"];
    const ws = ["ws2_32.dll"];

    // 콘솔 / 디버그 문자열
    kernel.forEach(m=>{
        safeAttachOrScan(m, "OutputDebugStringA", true);
        safeAttachOrScan(m, "OutputDebugStringW", false);
        safeAttachOrScan(m, "WriteConsoleA", true);
        safeAttachOrScan(m, "WriteConsoleW", false);
        safeAttachOrScan(m, "WriteFile", true);
    });

    // GUI 알림
    user.forEach(m=>{
        safeAttachOrScan(m, "MessageBoxA", true, 1);
        safeAttachOrScan(m, "MessageBoxW", false, 1);
        safeAttachOrScan(m, "SendMessageA", true, 2);
        safeAttachOrScan(m, "SendMessageW", false, 2);
    });

    // 네트워크
    ws.forEach(m=>{
        safeAttachOrScan(m, "send", true, 1);
        safeAttachOrScan(m, "recv", true, 1);
    });

    console.log("[*] Hook setup complete");
});

// 안전 attach 또는 Scan
function safeAttachOrScan(moduleName, funcName, isAnsi, argIndex){
    argIndex = argIndex || 0;
    let addr = null;
    try { addr = Module.findExportByName(moduleName, funcName); } catch(e){}
    if(addr){
        hookFunction(addr, funcName, function(args){
            try{
                const s = isAnsi? safeReadAnsi(args[argIndex]): safeReadUtf16(args[argIndex]);
                dump(funcName, s);
            }catch(e){}
        });
    } else {
        // Export 없으면 모듈 심볼 스캔
        try {
            const syms = Module.findSymbols(moduleName);
            syms.forEach(s=>{
                if(s.name.indexOf(funcName)>=0){
                    hookFunction(s.address, funcName, function(args){
                        try{
                            const s = isAnsi? safeReadAnsi(args[argIndex]): safeReadUtf16(args[argIndex]);
                            dump(funcName, s);
                        }catch(e){}
                    });
                }
            });
        } catch(e){}
    }
}
