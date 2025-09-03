// ===== 설정 =====
const varAddress = 0x14005000; // IDA에서 나온 숫자 주소(.rdata)

// ===== 문자열 읽기 =====
try {
    const strPtr = ptr(varAddress);           // Frida NativePointer로 변환
    const str = strPtr.readUtf8String();      // Frida 17+ 방식으로 문자열 읽기
    console.log("[*] 변수에 저장된 문자열:", str);
} catch(e) {
    console.log("[!] 문자열 읽기 실패:", e);
}
