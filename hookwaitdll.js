function waitForModuleAndHook(dllName, idaFuncAddr, idaDllBase) {
    var intv = setInterval(function () {
        var m = Process.findModuleByName(dllName);
        if (m) {
            clearInterval(intv);

            var rva = idaFuncAddr - idaDllBase;
            var target = m.base.add(rva);

            console.log("[+] 모듈 로드됨:", m.name, "base =", m.base);
            console.log("[+] IDA FuncAddr =", ptr(idaFuncAddr));
            console.log("[+] RVA =", ptr(rva));
            console.log("[+] Hook Addr =", target);

            Interceptor.attach(target, {
                onEnter: function (args) {
                    console.log("[*] 내가 원한 주소 실행됨! arg0 =", args[0]);
                },
                onLeave: function (retval) {
                    console.log("[*] 함수 종료, retval =", retval);
                }
            });

            console.log("[+] 후킹 완료, 해당 주소 호출 시 콘솔 찍힘!");
        }
    }, 100);
}

// 사용 예시
waitForModuleAndHook("myplugin.dll", 0x1010A0, 0x10000000);
