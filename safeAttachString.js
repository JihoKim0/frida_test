// ===== 설정 =====
const dllName = "myplugin.dll";       // 후킹할 DLL 이름
const idaFuncAddr = 0x1010A0;         // IDA에서 확인한 함수 시작 주소 (ImageBase 기준)
const idaDllBase = 0x10000000;        // IDA에서 본 DLL ImageBase
const newStringValue = "HelloFrida";  // 덮어쓸 문자열

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

                    // 새 문자열 메모리 할당
                    const newStrPtr = Memory.allocUtf8String(newStringValue);

                    console.log("    원래 eax 값:", this.context.eax);
                    console.log("    새 문자열 주소:", newStrPtr);

                    // eax에 문자열 주소 덮어쓰기
                    this.context.eax = newStrPtr;

                    console.log("    덮어쓴 후 eax 값:", this.context.eax);
                },
                onLeave: function(retval) {
                    console.log("[*] 함수 종료");
                }
            });

            console.log("[+] 후킹 완료, 함수 호출 시 eax 문자열 덮어쓰기 적용됨!");
        }
    }, 100);
}

// 실행
waitForModuleAndHook();
