"""User-bound Windows DPAPI protection for local integration credentials."""

import base64
import ctypes
import sys
from ctypes import wintypes


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, *, decrypt: bool) -> bytes:
    if sys.platform != "win32":
        raise ValueError("Сохранение API Token поддерживается только в Windows.")
    buffer = ctypes.create_string_buffer(data)
    source = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = _Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.argtypes = [
        ctypes.POINTER(_Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_Blob),
    ]
    function.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ValueError("Windows не удалось защитить или прочитать API Token.")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel32.LocalFree(target.data)


def protect_secret(secret: str) -> str:
    return base64.b64encode(_crypt(secret.encode("utf-8"), decrypt=False)).decode("ascii")


def unprotect_secret(protected: str) -> str:
    try:
        return _crypt(base64.b64decode(protected, validate=True), decrypt=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError("API Token недоступен. Введите и сохраните его заново.") from error
