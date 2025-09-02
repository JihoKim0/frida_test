// hook_strings.js
// Common Windows APIs that surface strings -> print them out.

'use strict';

// ---------- helpers ----------
function safeReadAnsi(ptr) {
  try { return ptr.readAnsiString(); } catch (_) { return null; }
}
function safeReadUtf16(ptr) {
  try { return ptr.readUtf16String(); } catch (_) { return null; }
}

function isLikelyTextFromBuf(ptr, len) {
  // quick heuristic: if many NULs -> probably UTF-16
  // else if bytes are mostly printable -> UTF-8/ANSI
  if (len <= 0 || ptr.isNull()) return null;
  const k = Math.min(len, 256);
  let nul = 0, printable = 0;
  const bytes = ptr.readByteArray(k);
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) {
    const b = view[i];
    if (b === 0x00) nul++;
    if (b >= 0x09 && b <= 0x0d) printable++; // \t..\r
    else if (b >= 0x20 && b <= 0x7e) printable++;
  }
  const nulRatio = nul / k;
  const printRatio = printable / k;

  if (nulRatio > 0.2) { // likely UTF-16
    try {
      return ptr.readUtf16String(len); // len = chars for W APIs, bytes for byte buffers; still OK-ish
    } catch (_) { /* fallthrough */ }
    try {
      return ptr.readUtf16String(); // null-terminated
    } catch (_) { return null; }
  }
  if (printRatio > 0.6) {
    try {
      return ptr.readUtf8String(len);
    } catch (_) {
      try { return ptr.readAnsiString(len); } catch (_) { return null; }
    }
  }
  return null;
}

function dumpLine(tag, text) {
  if (!text) return;
  const one = text
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");
  console.log(`[${tag}] ${one}`);
}

// ---------- hook helpers ----------
function hookAnsiW(moduleName, nameA, argSpecA, nameW, argSpecW, onLog) {
  const m = Module.findBaseAddress(moduleName);
  if (!m) return;

  const fnA = Module.findExportByName(moduleName, nameA);
  if (fnA) {
    Interceptor.attach(fnA, {
      onEnter(args) { try { onLog(`${moduleName}!${nameA}`, args, argSpecA, false); } catch (_) {} }
    });
  }
  const fnW = Module.findExportByName(moduleName, nameW);
  if (fnW) {
    Interceptor.attach(fnW, {
      onEnter(args) { try { onLog(`${moduleName}!${nameW}`, args, argSpecW, true); } catch (_) {} }
    });
  }
}

// Read LPCSTR/LPCWSTR parameter by index
function logLpcStr(apiName, args, idx, isWide) {
  const p = args[idx];
  const s = isWide ? safeReadUtf16(p) : safeReadAnsi(p);
  if (s) dumpLine(apiName, s);
}

// Read buffer + length pair (bufIdx, lenIdx)
function logBufLen(apiName, args, bufIdx, lenIdx) {
  const buf = args[bufIdx];
  const len = args[lenIdx].toUInt32();
  const s = isLikelyTextFromBuf(buf, len);
  if (s) dumpLine(apiName, s);
}

// ---------- concrete hooks ----------

// OutputDebugStringA/W: OutputDebugString(LPCSTR/LPCWSTR lpOutputString)
hookAnsiW("kernel32.dll",
  "OutputDebugStringA", [0],
  "OutputDebugStringW", [0],
  (api, args, spec, isWide) => logLpcStr(api, args, spec[0], isWide)
);

// MessageBoxA/W: MessageBox(hWnd, lpText, lpCaption, uType)
hookAnsiW("user32.dll",
  "MessageBoxA", [1, 2],
  "MessageBoxW", [1, 2],
  (api, args, spec, isWide) => {
    logLpcStr(api + " [Text]", args, spec[0], isWide);
    logLpcStr(api + " [Caption]", args, spec[1], isWide);
  }
);

// WriteConsoleA/W: WriteConsole(hOut, lpBuffer, nCharsToWrite, ...)
hookAnsiW("kernel32.dll",
  "WriteConsoleA", [1, 2],
  "WriteConsoleW", [1, 2],
  (api, args, spec, isWide) => {
    const buf = args[spec[0]];
    const nChars = args[spec[1]].toUInt32();
    let s = null;
    try {
      s = isWide ? buf.readUtf16String(nChars) : buf.readUtf8String(nChars);
    } catch (_) {}
    if (!s) s = isLikelyTextFromBuf(buf, nChars * (isWide ? 2 : 1));
    if (s) dumpLine(api, s);
  }
);

// WriteFile: WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, ...)
{
  const addr = Module.findExportByName("kernel32.dll", "WriteFile");
  if (addr) {
    Interceptor.attach(addr, {
      onEnter(args) {
        try { logBufLen("kernel32!WriteFile", args, 1, 2); } catch (_) {}
      }
    });
  }
}

// send: int send(SOCKET s, const char *buf, int len, int flags)
{
  const addr = Module.findExportByName("ws2_32.dll", "send");
  if (addr) {
    Interceptor.attach(addr, {
      onEnter(args) {
        try { logBufLen("ws2_32!send", args, 1, 2); } catch (_) {}
      }
    });
  }
}

// WSASend: uses WSABUF array; we’ll walk each buffer and try to print
{
  const addr = Module.findExportByName("ws2_32.dll", "WSASend");
  if (addr) {
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          const lpBuffers = args[1];
          const count = args[2].toUInt32();
          for (let i = 0; i < count; i++) {
            const WSABUF_SIZE = Process.pointerSize * 2; // ULONG len; CHAR* buf; but layout is {ULONG len; PCHAR buf}
            const cur = lpBuffers.add(WSABUF_SIZE * i);
            const len = cur.readU32();
            const bufPtr = cur.add(Process.pointerSize).readPointer();
            const s = isLikelyTextFromBuf(bufPtr, len);
            if (s) dumpLine("ws2_32!WSASend", s);
          }
        } catch (_) {}
      }
    });
  }
}

// HttpSendRequestA/W: (hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
hookAnsiW("wininet.dll",
  "HttpSendRequestA", [1, 2, 3, 4],
  "HttpSendRequestW", [1, 2, 3, 4],
  (api, args, spec, isWide) => {
    // headers
    const hdrPtr = args[spec[0]];
    const hdrLen = args[spec[1]].toInt32();
    if (!hdrPtr.isNull() && hdrLen > 0) {
      const hs = isWide ? hdrPtr.readUtf16String(hdrLen / 2) : hdrPtr.readUtf8String(hdrLen);
      if (hs) dumpLine(api + " [headers]", hs);
    }
    // optional data (body)
    const bodyPtr = args[spec[2]];
    const bodyLen = args[spec[3]].toInt32();
    if (!bodyPtr.isNull() && bodyLen > 0) {
      const bs = isLikelyTextFromBuf(bodyPtr, bodyLen);
      if (bs) dumpLine(api + " [body]", bs);
    }
  }
);

// Optional: CreateProcessA/W to see command-lines
hookAnsiW("kernel32.dll",
  "CreateProcessA", [1, 2], // lpApplicationName, lpCommandLine
  "CreateProcessW", [1, 2],
  (api, args, spec, isWide) => {
    logLpcStr(api + " [app]", args, spec[0], isWide);
    logLpcStr(api + " [cmd]", args, spec[1], isWide);
  }
);

console.warn("[*] string hooks installed");
