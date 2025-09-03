var dllName = "your.dll";  // IDA에서 확인한 DLL 이름
var idaAddr = 0x401000;    // IDA에서 확인한 함수/코드 주소
var fileBase = 0x400000;   // DLL이 IDA에서 로드된 기본 주소 (보통 PE 헤더 시작)

var baseAddr = Module.findBaseAddress(dllName);
if (baseAddr === null) {
    console.log(dllName + " 로드 안됨!");
} else {
    var hookAddr = baseAddr.add(idaAddr - fileBase);
    console.log("후킹 주소:", hookAddr);

    Interceptor.attach(hookAddr, {
        onEnter: function(args) {
            console.log("함수 진입!");
        },
        onLeave: function(retval) {
            console.log("함수 종료, 반환값:", retval);
        }
    });
}
