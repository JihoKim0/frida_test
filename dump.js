// ===== 설정 =====
const varAddr = ptr(0x14005000);  // IDA에서 나온 .rdata 주소
const len = 32;                   // 확인할 바이트 길이

try {
    const bytes = new Uint8Array(varAddr.readByteArray(len));
    let hexDump = "";
    for (let i = 0; i < bytes.length; i++) {
        hexDump += bytes[i].toString(16).padStart(2, "0") + " ";
    }
    console.log("[*] Hex Dump:", hexDump.trim());
} catch(e) {
    console.log("[!] Hex Dump 읽기 실패:", e);
}
