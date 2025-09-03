// ===== 설정 =====
const dllName = "myplugin.dll";       // 후킹할 DLL 이름
const idaFuncAddr = 0x1010A0;         // IDA에서 확인한 함수 시작 주소 (ImageBase 기준)
const idaDllBase = 0x10000000;        // IDA에서 본 DLL ImageBase
const newStringValue = "HelloFrida";  // 덮어쓸 새 문자열

// ===== DLL 로드 대기 및 후킹 =====
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

                    // eax(또는 x64 rax) 레지스터 확인
                    const eaxVal = this.context.eax;  // x64면 rax
                    console.log("    원래 eax 주소:", ptr(eaxVal));

                    // 안전하게 문자열 읽기
                    try {
                        const maxLen = 64;
                        const bytes = Memory.readByteArray(ptr(eaxVal), maxLen);
                        let str = '';
                        const uint8arr = new Uint8Array(bytes);
                        for (let i = 0; i < uint8arr.length; i++) {
                            if (uint8arr[i] === 0) break;
                            str += String.fromCharCode(uint8arr[i]);
                        }
                        console.log("    eax가 가리키는 문자열:", str);
                    } catch (e) {
                        console.log("    문자열 읽기 실패:", e);
                    }

                    // 새 문자열로 덮어쓰기
                    const newStrPtr = Memory.allocUtf8String(newStringValue);
                    this.context.eax = newStrPtr;
                    console.log("    eax를 새 문자열 주소로 변경:", ptr(this.context.eax));
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
