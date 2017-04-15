// DNSTCP.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if(argc == 1)
	{
		printf("若需安全结束此进程，请按 Ctrl+C\n");
		printf("若需将此程序注册为服务，请以管理员身份运行并使用参数 install\n");
		printf("若需删除已注册的服务，请以管理员身份运行并使用参数 remove\n");
		return MainDebug();
	}

	if(_stricmp(argv[1], "service") == 0)
	{
		return MainService();
	}

	if(_stricmp(argv[1], "install") == 0)
	{
		if(InstallNTService())
			printf("%s 服务安装成功\n", lpServiceName);
		else
			printf("%s 服务安装失败\n", lpServiceName);
	}

	if(_stricmp(argv[1], "remove") == 0)
	{
		if(RemoveNTService())
			printf("%s 服务删除成功\n", lpServiceName);
		else
			printf("%s 服务删除失败\n", lpServiceName);
	}

	return 0;
}