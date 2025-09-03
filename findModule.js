// 후킹할 모듈 이름
var moduleName = "target.exe"; // 실행파일 이름
// IDA에서 확인한 주소 (예: 0x401000)
var targetAddrIDA = 0x401000;

// 모듈 베이스 주소 가져오기
var baseAddr = Module.findBaseAddress(moduleName);
if (baseAddr === null) {
    console.log("모듈을 찾을 수 없음");
} else {
    // IDA 절대 주소에서 모듈 베이스를 빼고 ptr로 변환
    var offset = targetAddrIDA - baseAddr.toInt32();
    var hookAddr = baseAddr.add(offset);

    console.log("후킹 주소:", hookAddr);

    // 함수 후킹
    Interceptor.attach(hookAddr, {
        onEnter: function(args) {
            console.log("함수 진입!");
            // args[0], args[1] 등 인자 확인 가능
        },
        onLeave: function(retval) {
            console.log("함수 종료, 반환값:", retval);
        }
    });
}
