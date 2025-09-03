// ====== 사용자 설정 부분 ======
var dllPath = "C:\\경로\\to\\myplugin.dll"; // DLL 절대경로
var dllName = "myplugin.dll";                // DLL 이름 (Module.load 후 참조용)
var idaFuncAddr = 0x1010A0;                  // IDA에서 확인한 함수 주소
var idaDllBase = 0x10000000;                 // IDA에서 본 DLL 시작 주소 (PE 헤더 기준)
// ==============================

function hookUserDll() {
    var baseAddr = Module.findBaseAddress(dllName);

    if (baseAddr === null) {
        console.log(dllName + " 로드 실패!");
        return;
    }

    // IDA 주소 → Frida 후킹 주소 변환
    var hookAddr = baseAddr.add(idaFuncAddr - idaDllBase);
    console.log("[+] 후킹 주소 계산 완료:", hookAddr);

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

    console.log("[+] 후킹 성공!");
}

// DLL이 이미 로드됐는지 확인
if (Module.findBaseAddress(dllName) === null)
