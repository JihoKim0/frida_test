'use strict';

// 확인할 주소 입력 (IDA에서 확인한 값)
// 32비트면 ptr("0x12345678"), 64비트면 ptr("0x12345678") 그대로
var targetAddr = ptr("0x12345678");

// 읽을 바이트 길이 (예: 100바이트)
var length = 100;

setInterval(function(){
    try {
        var value = Memory.readUtf8String(targetAddr); // ANSI 문자열
        if(value) console.log("[+] Memory @ " + targetAddr + " : " + value);
    } catch(e){
        console.log("[!] Cannot read memory @ " + targetAddr + " : " + e.message);
    }
}, 500); // 0.5초마다 체크
