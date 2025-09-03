// ===== 설정 =====
const dllName = "myplugin.dll";      // 후킹할 DLL 이름
const variableOffset = 0x5000;       // IDA에서 확인한 변수 주소 - DLL ImageBase

// ===== DLL 로드 감지 및 문자열 읽기 =====
function waitForModuleAndReadVar() {
    const interval = setInterval(() => {
        const mod = Process.findModuleByName(dllName);
        if (mod) {
            clearInterval(interval);

            // 변수 실제 메모리 주소 계산
            const varAddr = mod.base.add(variableOffset);

            console.log("[+] DLL 로드됨:", mod.name, "base =", mod.base);
            console.log("[+] 변수 실제 주소 계산:", varAddr);

            // 문자열 읽기
            try {
                const str = varAddr.readUtf8String();  // Frida 17+ 방식
                console.log("[*] 변수에 저장된 문자열:", str);
            } catch (e) {
                console.log("[!] 문자열 읽기 실패:", e);
            }
        }
    }, 100);
}

// 실행
waitForModuleAndReadVar();
