#pragma once
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <Evntprov.h>
#include "Manifest\ETW.h"
#include "sha4.h"

const void *find_pattern(HANDLE module, std::string name, const char *pattern, const char *mask, size_t size);