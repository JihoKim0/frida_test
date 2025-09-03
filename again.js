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

function dump(tag,str){
    if(str) console.log(`[${tag}] ${str.replace(/\r/g,'\\r').replace(/\n/g,'\\n')}`);
}

// ----------------- 안전 attach -----------------
function safeAttach(modules, funcName, callback){
    let addr = null;
    for(let m of modules){
        try { 
            addr = Module.findExportByName(m, funcName); 
            if(addr) break; 
        } catch(e){}
    }

    // Export 못 찾으면 심볼 스캔
    if(!addr){
        for(let m of modules){
            try {
                const syms = Module.findSymbols(m);
                for(let s of syms){
                    if(s.name.indexOf(funcName)>=0){
                        addr = s.address;
                        break;
                    }
                }
                if(addr) break;
            } catch(e){}
        }
    }

    if(!addr){
        console.warn(`[!] ${funcName} not found in ${modules.join(", ")}`);
        return;
    }

    Interceptor.attach(addr,{onEnter:callback});
    console.log(`[+] Hooked ${funcName} @ ${addr}`);
}

// ----------------- 후킹 함수 정의 -----------------
function hookAll(){
    const kernelModules = ["kernel32.dll","KERNELBASE.dll"];
    const userModules = ["user32.dll"];
    const wsModules = ["ws2_32.dll"];

    // OutputDebugString
    safeAttach(kernelModules, "OutputDebugStringA", (args)=>dump("OutputDebugStringA", safeReadAnsi(args[0])));
    safeAttach(kernelModules, "OutputDebugStringW", (args)=>dump("OutputDebugStringW", safeReadUtf16(args[0])));

    // WriteConsole
    safeAttach(kernelModules, "WriteConsoleA", (args)=>{
        const buf=args[1], len=args[2]?args[2].toInt32():0;
        if(buf && len>0) try{ dump("WriteConsoleA", buf.readAnsiString(len)); }catch(e){}
    });
    safeAttach(kernelModules, "WriteConsoleW", (args)=>{
        const buf=args[1], len=args[2]?args[2].toInt32():0;
        if(buf && len>0) try{ dump("WriteConsoleW", buf.readUtf16String(len)); }catch(e){}
    });

    // MessageBox
    safeAttach(userModules, "MessageBoxA", (args)=>{
        dump("MessageBoxA[Text]", safeReadAnsi(args[1]));
        dump("MessageBoxA[Caption]", safeReadAnsi(args[2]));
    });
    safeAttach(userModules, "MessageBoxW", (args)=>{
        dump("MessageBoxW[Text]", safeReadUtf16(args[1]));
        dump("MessageBoxW[Caption]", safeReadUtf16(args[2]));
    });

    // SendMessage
    safeAttach(userModules, "SendMessageA", (args)=>{
        const buf=args[2]; if(buf) dump("SendMessageA", safeReadAnsi(buf));
    });
    safeAttach(userModules, "SendMessageW", (args)=>{
        const buf=args[2]; if(buf) dump("SendMessageW", safeReadUtf16(buf));
    });

    // WriteFile
    safeAttach(kernelModules, "WriteFile", (args)=>{
        const buf=args[1], len=args[2]?args[2].toInt32():0;
        if(buf && len>0) try{ dump("WriteFile", buf.readAnsiString(len)); }catch(e){}
    });

    // send/recv
    safeAttach(wsModules, "send", (args)=>{
        const buf=args[1], len=args[2]?args[2].toInt32():0;
        if(buf && len>0) try{ dump("send", buf.readAnsiString(len)); }catch(e){}
    });
    safeAttach(wsModules, "recv", (args)=>{
        const buf=args[1], len=args[2]?args[2].toInt32():0;
        if(buf && len>0) try{ dump("recv", buf.readAnsiString(len)); }catch(e){}
    });

    console.log("[*] All string hooks installed safely");
}

// ----------------- 모듈 로드 이벤트 -----------------
Module.on("load", function(m){
    const name = m.name.toLowerCase();
    if(name.indexOf("kernel32.dll")>=0 || name.indexOf("kernelbase.dll")>=0 ||
       name.indexOf("user32.dll")>=0 || name.indexOf("ws2_32.dll")>=0){
        console.log("[*] Loaded module:", m.name);
        hookAll();
    }
});

// ----------------- 이미 로드된 모듈도 처리 -----------------
hookAll();
