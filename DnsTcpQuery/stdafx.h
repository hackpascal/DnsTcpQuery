// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <memory.h>
#include <malloc.h>



// TODO: 在此处引用程序需要的其他头文件
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>
#include <winsock2.h>
#include <winsock.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <process.h>

#include "service.h"
#include "thread.h"
#include "network.h"
#include "regex.h"
#include "param.h"
#include "cache.h"