// ===== 설정 =====
const dllName = "myplugin.dll";       // 후킹할 DLL 이름
const variableOffset = 0x5000;        // IDA에서 확인한 변수 주소 - DLL ImageBase
const newStringValue = "FridaRocks!!Extra"; // 기존보다 길이 긴 문자열

// ===== DLL 로드 대기 및 문자열 읽기/변조 =====
function waitForModuleAndModifyVar() {
    const interval = setInterval(() => {
        const mod = Process.findModuleByName(dllName);
        if (mod) {
            clearInterval(interval);

            // 변수 실제 메모리 주소 계산
            const varAddr = mod.base.add(variableOffset);

            console.log("[+] DLL 로드됨:", mod.name, "base =", mod.base);
            console.log("[+] 변수 실제 주소 계산:", varAddr);

            try {
                // 원래 문자열 읽기
                const origStr = varAddr.readUtf8String();
                console.log("[*] 원래 문자열:", origStr);

                // 길이 늘어난 문자열을 새 메모리에 할당
                const newStrPtr = Memory.allocUtf8String(newStringValue);

                // 포인터 자체를 교체하고 싶으면 eax 같은 레지스터 덮어쓰기 필요
                // 여기서는 변수 메모리 직접 덮어쓰기
                Memory.copy(varAddr, newStrPtr, newStringValue.length + 1); // +1: null terminator

                // 덮어쓴 후 확인
                const modifiedStr = varAddr.readUtf8String();
                console.log("[*] 덮어쓴 후 문자열:", modifiedStr);

            } catch (e) {
                console.log("[!] 문자열 읽기/변조 실패:", e);
            }
        }
    }, 100);
}

// 실행
waitForModuleAndModifyVar();
