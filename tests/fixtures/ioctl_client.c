/* A user-mode client of in-box devices: the driver boundary without a driver of ours (plan decision 6,
   docs/trace-fixtures.md).
   usage: ioctl_client.exe
   Opens \\.\NUL and \\.\Beep and issues control codes and I/O. Every call has a fixed code, buffer and size, so the
   user-mode boundary events (CreateFile, DeviceIoControl, WriteFile, ReadFile, CloseHandle, with codes, buffer sizes
   and status) are known in advance:
     NUL:  fx_nul_write writes 16 bytes ("HYDRA-IOCTL-NUL!") and gets 16 written; fx_nul_read reads 0 bytes (EOF);
           fx_nul_ioctl sends code 0x00152000 (FILE_DEVICE_NULL, function 0x800, buffered) with the 8 input bytes
           "HYDRAIOC": the NUL device rejects it (ERROR_INVALID_FUNCTION, 1).
     Beep: fx_beep_stop sends IOCTL_BEEP_SET (0x00010000) with BEEP_SET_PARAMETERS {frequency 0, duration 0}, which
           silences the speaker and makes no sound; fx_beep_bad sends it with a 4-byte input, which the driver
           rejects. Whether the Beep device can be opened at all depends on the machine, so those results are
           environment-dependent (the outcome is printed, never asserted). */
#include "trace_common.h"
#include <winioctl.h>

#define IOCTL_NUL_PROBE CTL_CODE(0x15, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEEP_SET_CODE CTL_CODE(1, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct BeepParameters { DWORD frequency, duration; } BeepParameters;

FX HANDLE fx_open_device(const wchar_t *path) {
    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

FX int fx_nul_write(HANDLE device) {
    DWORD written = 0;
    BOOL ok = WriteFile(device, "HYDRA-IOCTL-NUL!", 16, &written, NULL);
    say("nul_write ok=%d written=%lu", ok, written);
    return ok && written == 16;
}

FX int fx_nul_read(HANDLE device) {
    char buffer[16];
    DWORD got = 99;
    BOOL ok = ReadFile(device, buffer, sizeof buffer, &got, NULL);
    say("nul_read ok=%d got=%lu", ok, got);
    return got == 0;
}

FX int fx_nul_ioctl(HANDLE device) {
    DWORD returned = 0;
    char output[8] = { 0 };
    BOOL ok = DeviceIoControl(device, IOCTL_NUL_PROBE, "HYDRAIOC", 8, output, sizeof output, &returned, NULL);
    DWORD error = ok ? 0 : GetLastError();
    say("nul_ioctl code=0x%08lx ok=%d error=%lu returned=%lu", (unsigned long)IOCTL_NUL_PROBE, ok, error, returned);
    return !ok && error == ERROR_INVALID_FUNCTION;
}

FX int fx_beep_stop(HANDLE device) {
    BeepParameters parameters = { 0, 0 };
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_BEEP_SET_CODE, &parameters, sizeof parameters, NULL, 0, &returned, NULL);
    say("beep_stop code=0x%08lx ok=%d error=%lu", (unsigned long)IOCTL_BEEP_SET_CODE, ok, ok ? 0 : GetLastError());
    return ok;
}

FX int fx_beep_bad(HANDLE device) {
    DWORD returned = 0, short_input = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_BEEP_SET_CODE, &short_input, 4, NULL, 0, &returned, NULL);
    say("beep_bad code=0x%08lx ok=%d error=%lu", (unsigned long)IOCTL_BEEP_SET_CODE, ok, ok ? 0 : GetLastError());
    return !ok;
}

int main(void) {
    fx_arm_watchdog(30);
    HANDLE nul = fx_open_device(L"\\\\.\\NUL");
    say("nul_open ok=%d", nul != INVALID_HANDLE_VALUE);
    if (nul == INVALID_HANDLE_VALUE) return 3;
    int nul_ok = fx_nul_write(nul) && fx_nul_read(nul) && fx_nul_ioctl(nul);
    CloseHandle(nul);
    HANDLE beep = fx_open_device(L"\\\\.\\Beep");
    say("beep_open ok=%d", beep != INVALID_HANDLE_VALUE);
    if (beep != INVALID_HANDLE_VALUE) {
        fx_beep_stop(beep);
        fx_beep_bad(beep);
        CloseHandle(beep);
    }
    say("done");
    return nul_ok ? 0 : 1;
}
