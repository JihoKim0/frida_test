// ====== 사용자 설정 ======
var dllPath = "C:\\경로\\to\\myplugin.dll"; // DLL 절대경로
var dllName = "myplugin.dll";                // DLL 이름 (로드 후 참조용)
// ============================

var loaded = false;

function checkDll() {
    if (loaded) return;

    try {
        // Frida 17 이상에서는 Process.getModuleByName 사용
        var module = Process.getModuleByName(dllName);
        if (module !== null) {
            loaded = true;
            console.log("[+] " + dllName + " 로드됨! 베이스 주소:", module.base);
        }
    } catch (e) {
        // 모듈 없으면 예외 발생, 무시
        // console.log(dllName + " 아직 로드되지 않음");
    }
}

// DLL이 처음부터 로드되지 않았으면 절대경로로 강제 로드
try {
    Module.load(dllPath);
} catch (e) {
    console.log("[!] DLL 로드 실패:", e);
}

// 주기적으로 체크 (100ms)
setInterval(checkDll, 100);
