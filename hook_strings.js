// hook_strings_fixed.js
'use strict';

// ---------- safe readers ----------
function safeReadAnsi(ptr) {
  if (!ptr || (ptr.isNull && ptr.isNull())) return null;
  try { return ptr.readCString(); } catch (e) {}
  try { return ptr.readUtf8String(); } catch (e) {}
  return null;
}
function safeReadUtf16(ptr) {
  if (!ptr || (ptr.isNull && ptr.isNull())) return null;
  try { return ptr.readUtf16String(); } catch (e) { return null; }
}

function isLikelyTextFromBuf(ptr, len) {
  if (!ptr || (ptr.isNull && ptr.isNull())) return null;
  if (!len || len <= 0) return null;
  const k = Math.min(len, 512);
  try {
    const bytes = ptr.readByteArray(k);
    if (!bytes) return null;
    const view = new Uint8Array(bytes);
    let nul = 0, printable = 0;
    for (let i = 0; i < view.length; i++) {
      const b = view[i];
      if (b === 0x00) nul++;
      if ((b >= 0x09 && b <= 0x0d) || (b >= 0x20 && b <= 0x7e)) printable++;
    }
    const nulRatio = nul / view.length;
    const printRatio = printable / view.length;

    if (nulRatio > 0.2) {
      try { return ptr.readUtf16String(len/2); } catch (e) {}
      try { return ptr.readUtf16String(); } catch (e) {}
    }
    if (printRatio > 0.6) {
      try { return ptr.readUtf8String(len); } catch(e) {}
      try { return ptr.readCString(); } catch(e) {}
    }
  } catch (e) {}
  return null;
}

function dumpLine(tag, text) {
  if (!text) return;
  const one = text.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
  console.log(`[${tag}] ${one}`);
}

// ---------- robust attach helper ----------
function tryAttachExport(moduleName, exportName, callbacks, retries = 6, delay = 250) {
  let attempts = 0;
  const _try = function() {
    const addr = Module.findExportByName(moduleName, exportName);
    if (addr) {
      try {
        Interceptor.attach(addr, callbacks);
        console.log(`[+] attached ${moduleName}!${exportName}`);
      } catch (e) {
        console.warn(`[!] attach failed ${moduleName}!${exportName}: ${e}`);
      }
      return;
    }
    attempts++;
    if (attempts <= retries) {
      setTimeout(_try, delay);
    } else {
      console.warn(`[!] export not found: ${moduleName}!${exportName} (after ${attempts} tries)`);
    }
  };
  _try();
}

// ---------- safer hookAnsiW ----------
function hookAnsiW(moduleName, nameA, argSpecA, nameW, argSpecW, onLog) {
  if (typeof onLog !== 'function') {
    console.warn("[hookAnsiW] onLog must be a function");
    return;
  }

  if (nameA) {
    tryAttachExport(moduleName, nameA, {
      onEnter(args) {
        try { onLog(`${moduleName}!${nameA}`, args, argSpecA, false); } catch (e) { console.warn("onEnter callback error:", e); }
      }
    });
  }

  if (nameW) {
    tryAttachExport(moduleName, nameW, {
      onEnter(args) {
        try { onLog(`${moduleName}!${nameW}`, args, argSpecW, true); } catch (e) { console.warn("onEnter callback error:", e); }
      }
    });
  }
}

// ---------- small log helpers ----------
function logLpcStr(apiName, args, idx, isWide) {
  const p = args[idx];
  if (!p || (p.isNull && p.isNull())) return;
  const s = isWide ? safeReadUtf16(p) : safeReadAnsi(p);
  if (s) dumpLine(apiName, s);
}
function logBufLen(apiName, args, bufIdx, lenIdx) {
  const buf = args[bufIdx];
  const len = (args[lenIdx] && args[lenIdx].toInt32) ? args[lenIdx].toInt32() : 0;
  if (!buf || (buf.isNull && buf.isNull())) return;
  const s = isLikelyTextFromBuf(buf, len);
  if (s) dumpLine(apiName, s);
}

// ---------- concrete hooks (examples) ----------
hookAnsiW("kernel32.dll", "OutputDebugStringA", [0], "OutputDebugStringW", [0],
  (api, args, spec, isWide) => logLpcStr(api, args, spec[0], isWide)
);

hookAnsiW("user32.dll", "MessageBoxA", [1,2], "MessageBoxW", [1,2],
  (api, args, spec, isWide) => {
    logLpcStr(api + " [Text]", args, spec[0], isWide);
    logLpcStr(api + " [Caption]", args, spec[1], isWide);
  }
);

hookAnsiW("kernel32.dll", "WriteConsoleA", [1,2], "WriteConsoleW", [1,2],
  (api, args, spec, isWide) => {
    const buf = args[spec[0]];
    const n = (args[spec[1]] && args[spec[1]].toInt32) ? args[spec[1]].toInt32() : 0;
    if (!buf || (buf.isNull && buf.isNull())) return;
    try {
      const s = isWide ? buf.readUtf16String(n) : buf.readUtf8String(n);
      if (s) dumpLine(api, s);
    } catch (e) {
      const s2 = isLikelyTextFromBuf(buf, n * (isWide ? 2 : 1));
      if (s2) dumpLine(api, s2);
    }
  }
);

// 예시: WriteFile / send 등도 이전과 동일한 패턴으로 추가하면 됨

console.warn("[*] safer hooks installed");
