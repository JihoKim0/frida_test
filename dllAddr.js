// ====== 헬퍼 함수 ======
function hookByIdaAddr(dllName, idaFuncAddr, idaDllBase, callback) {
    var module = Process.getModuleByName(dllName);
    if (!module) {
        console.log("[!] 모듈 못찾음:", dllName);
        return;
    }

    // RVA = IDA 함수 주소 - IDA DLL Base
    var rva = idaFuncAddr - idaDllBase;
    var target = module.base.add(rva);

    console.log("[+] DLL:", dllName);
    console.log("    module.base =", module.base);
    console.log("    idaFuncAddr =", ptr(idaFuncAddr));
    console.log("    idaDllBase  =", ptr(idaDllBase));
    console.log("    RVA         =", ptr(rva));
    console.log("    Hook Addr   =", target);

    Interceptor.attach(target, {
        onEnter: function (args) {
            if (callback.onEnter) callback.onEnter.call(this, args);
        },
        onLeave: function (retval) {
            if (callback.onLeave) callback.onLeave.call(this, retval);
        }
    });

    console.log("[+] 후킹 완료!");
}

// ====== 실제 사용 ======
// 예: IDA에서 sub_1010A0, DLL ImageBase = 0x10000000
hookByIdaAddr("myplugin.dll", 0x1010A0, 0x10000000, {
    onEnter: function (args) {
        console.log("[*] 함수 진입! arg0 =", args[0].toInt32());
    },
    onLeave: function (retval) {
        console.log("[*] 함수 종료, retval =", retval.toInt32());
    }
});
