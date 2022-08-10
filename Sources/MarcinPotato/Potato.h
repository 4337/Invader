#pragma once

#include <Windows.h>
#include <tchar.h>
#include <shlwapi.h>
#include <cstdarg>

#define DEBUG_OUTPUT_SIZE 512

DWORD write_console(const TCHAR* format, ...) {

	DWORD ret = -1;

	va_list args = nullptr;

	va_start(args, format);

	TCHAR buff[DEBUG_OUTPUT_SIZE + 1] = { 0 };

	if (wvnsprintf(buff, DEBUG_OUTPUT_SIZE, format, args) > 0) {

		WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), buff, static_cast<DWORD>(_tcslen(buff)), &ret, NULL);

	}

	va_end(args);

	return ret;

}

