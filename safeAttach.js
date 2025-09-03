// ===== 설정 =====
const dllName = "myplugin.dll";       // 후킹할 DLL 이름
const idaFuncAddr = 0x1010A0;         // IDA에서 확인한 함수 시작 주소 (ImageBase 기준)
const idaDllBase = 0x10000000;        // IDA에서 본 DLL ImageBase
const newEaxValue = 0x12345678;       // 덮어쓸 새 값 (주소든 숫자든 가능)

// ===== DLL 로드 대기 및 함수 후킹 =====
function waitForModuleAndHook() {
    const interval = setInterval(() => {
        const mod = Process.findModuleByName(dllName);
        if (mod) {
            clearInterval(interval);

            // RVA 계산
            const rva = idaFuncAddr - idaDllBase;
            const target = mod.base.add(rva);

            console.log("[+] DLL 로드됨:", mod.name, "base =", mod.base);
            console.log("[+] 함수 후킹 주소 계산:", target);

            Interceptor.attach(target, {
                onEnter: function(args) {
                    console.log("[*] 함수 진입!");
                    console.log("    원래 eax 값:", this.context.eax);

                    // 안전하게 새 값 덮어쓰기
                    this.context.eax = newEaxValue;
                    console.log("    덮어쓴 후 eax 값:", this.context.eax);
                },
                onLeave: function(retval) {
                    console.log("[*] 함수 종료");
                }
            });

            console.log("[+] 후킹 완료, 함수 호출 시 eax 값 덮어쓰기 적용됨!");
        }
    }, 100);
}

// 실행
waitForModuleAndHook();
