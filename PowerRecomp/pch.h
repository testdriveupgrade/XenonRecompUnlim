#pragma once

// Workaround for the intellisense for some reason not seeing C++23 features
#ifdef __INTELLISENSE__
#undef __cplusplus
#define __cplusplus 202302L
#endif

#include <cassert>
#include <disasm.h>
#include <file.h>
#include <filesystem>
#include <format>
#include <function.h>
#include <image.h>
#include <print>
#include <toml++/toml.hpp>
#include <unordered_map>
#include <unordered_set>
#include <xbox.h>
#include <xxhash.h>
