#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include <string>
#include <regex>
#include <fstream>

#ifndef UNICODE  
using string_t = std::string;
using regex_t = std::regex;
using fstream_t = std::fstream;
#else
using string_t = std::wstring;
using regex_t = std::wregex;
using fstream_t = std::wfstream;
#endif

using binary_string = std::basic_string<unsigned char>;

#define __J_DEBUG__ true
#define __BE_KIND__ true

#ifndef WINDOWS_NTSTATUS_H
#define WINDOWS_NTSTATUS_H

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef NT_ERROR
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)
#endif

#endif 

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (P)
#endif

#endif
