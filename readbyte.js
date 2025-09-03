// ===== 설정 =====
const varAddress = 0x14005000; // IDA에서 나온 .rdata 변수 주소
const maxLen = 64;              // 읽을 최대 바이트 길이

// ===== 메모리 읽기 =====
const varPtr = ptr(varAddress);

console.log("[*] 변수 주소:", varPtr);

try {
    // UTF-8 시도
    try {
        const strUtf8 = varPtr.readUtf8String();
        console.log("[*] UTF-8 문자열:", strUtf8);
    } catch(e) {
        console.log("[!] UTF-8 읽기 실패:", e);
    }

    // UTF-16 시도
    try {
        const strUtf16 = varPtr.readUtf16String();
        console.log("[*] UTF-16 문자열:", strUtf16);
    } catch(e) {
        console.log("[!] UTF-16 읽기 실패:", e);
    }

    // 바이트 덤프
    try {
        const bytes = new Uint8Array(varPtr.readByteArray(maxLen));
        console.log("[*] 바이트 덤프:", bytes);
        let hexDump = "";
        for (let i = 0; i < bytes.length; i++) {
            hexDump += bytes[i].toString(16).padStart(2, "0") + " ";
        }
        console.log("[*] Hex Dump:", hexDump);
    } catch(e) {
        console.log("[!] 바이트 덤프 실패:", e);
    }

} catch(e) {
    console.log("[!] 변수 읽기 실패:", e);
}
