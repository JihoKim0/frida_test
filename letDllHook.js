// ====== 사용자 설정 ======
var dllName = "myplugin.dll";   // 이미 로드될 DLL 이름
var idaFuncAddr = 0x1010A0;     // IDA에서 확인한 함수 주소
var idaDllBase = 0x10000000;    // IDA에서 본 DLL 파일 시작 주소 (PE 헤더 기준)
// ==============================

var hooked = false;

function checkAndHook() {
    if (hooked) return;

    try {
        // DLL이 로드됐는지 확인
        var module = Process.getModuleByName(dllName);
        if (module !== null) {
            hooked = true;
            console.log("[+] " + dllName + " 로드됨, 베이스 주소:", module.base);

            // IDA 주소 → Frida 후킹 주소 변환
            var hookAddr = module.base.add(idaFuncAddr - idaDllBase);
            console.log("[+] 후킹 주소:", hookAddr);

            // 후킹
            Interceptor.attach(hookAddr, {
                onEnter: function(args) {
                    console.log("[+] 함수 진입!");
                    // args 확인 예시
                    try { console.log("args[0]:", args[0].toInt32()); } catch(e){}
                },
                onLeave: function(retval) {
                    console.log("[+] 함수 종료, 반환값:", retval);
                }
            });

            console.log("[+] 후킹 완료!");
        }
    } catch (e) {
        // 아직 로드되지 않았으면 예외 발생, 무시
    }
}

// 100ms마다 DLL 로드 여부 확인 및 후킹
setInterval(checkAndHook, 100);
