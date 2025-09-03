setImmediate(function() {
    // 모듈 초기화
    ["kernel32.dll", "KERNELBASE.dll", "user32.dll", "ws2_32.dll"].forEach(m => {
        try { Module.ensureInitialized(m); } catch(e) {}
    });

    function safeReadAnsi(ptr) { try { return ptr && !ptr.isNull() ? ptr.readCString() : null } catch(e){ return null; } }
    function safeReadUtf16(ptr){ try { return ptr && !ptr.isNull() ? ptr.readUtf16String() : null } catch(e){ return null; } }
    function dump(tag,str){ if(str) console.log(`[${tag}] ${str.replace(/\r/g,'\\r').replace(/\n/g,'\\n')}`); }

    // ------------------ 후킹 ------------------
    const hooks = [
        ["OutputDebugStringA", ["kernel32.dll","KERNELBASE.dll"], (args)=>dump("OutputDebugStringA", safeReadAnsi(args[0]))],
        ["OutputDebugStringW", ["kernel32.dll","KERNELBASE.dll"], (args)=>dump("OutputDebugStringW", safeReadUtf16(args[0]))],
        ["WriteConsoleA", ["kernel32.dll","KERNELBASE.dll"], (args)=>{
            const buf=args[1], len=args[2]?args[2].toInt32():0;
            if(buf && len>0) try{ dump("WriteConsoleA", buf.readAnsiString(len)); }catch(e){}
        }],
        ["WriteConsoleW", ["kernel32.dll","KERNELBASE.dll"], (args)=>{
            const buf=args[1], len=args[2]?args[2].toInt32():0;
            if(buf && len>0) try{ dump("WriteConsoleW", buf.readUtf16String(len)); }catch(e){}
        }],
        ["MessageBoxA", ["user32.dll"], (args)=>{
            dump("MessageBoxA[Text]", safeReadAnsi(args[1]));
            dump("MessageBoxA[Caption]", safeReadAnsi(args[2]));
        }],
        ["MessageBoxW", ["user32.dll"], (args)=>{
            dump("MessageBoxW[Text]", safeReadUtf16(args[1]));
            dump("MessageBoxW[Caption]", safeReadUtf16(args[2]));
        }],
        ["SendMessageA", ["user32.dll"], (args)=>{
            const buf=args[2];
            if(buf) dump("SendMessageA", safeReadAnsi(buf));
        }],
        ["SendMessageW", ["user32.dll"], (args)=>{
            const buf=args[2];
            if(buf) dump("SendMessageW", safeReadUtf16(buf));
        }],
        ["WriteFile", ["kernel32.dll","KERNELBASE.dll"], (args)=>{
            const buf=args[1], len=args[2]?args[2].toInt32():0;
            if(buf && len>0) try{ dump("WriteFile", buf.readAnsiString(len)); }catch(e){}
        }],
        ["send", ["ws2_32.dll"], (args)=>{
            const buf=args[1], len=args[2]?args[2].toInt32():0;
            if(buf && len>0) try{ dump("send", buf.readAnsiString(len)); }catch(e){}
        }],
        ["recv", ["ws2_32.dll"], (args)=>{
            const buf=args[1], len=args[2]?args[2].toInt32():0;
            if(buf && len>0) try{ dump("recv", buf.readAnsiString(len)); }catch(e){}
        }]
    ];

    hooks.forEach(([name, modules, callback])=>{
        let addr = null;
        for(let m of modules){
            try { addr = Module.findExportByName(m,name); if(addr) break; } catch(e){}
        }
        if(addr){
            Interceptor.attach(addr,{onEnter:callback});
            console.log(`[+] Hooked ${name} @ ${addr}`);
        } else console.warn(`[!] ${name} not found in ${modules.join(", ")}`);
    });

    console.log("[*] All string hooks installed safely");
});
