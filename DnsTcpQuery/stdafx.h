// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <memory.h>
#include <malloc.h>



// TODO: �ڴ˴����ó�����Ҫ������ͷ�ļ�
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