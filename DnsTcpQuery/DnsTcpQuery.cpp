// DNSTCP.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

int _tmain(int argc, _TCHAR* argv[])
{
	if(argc == 1)
	{
		printf("���谲ȫ�����˽��̣��밴 Ctrl+C\n");
		printf("���轫�˳���ע��Ϊ�������Թ���Ա������в�ʹ�ò��� install\n");
		printf("����ɾ����ע��ķ������Թ���Ա������в�ʹ�ò��� remove\n");
		return MainDebug();
	}

	if(_stricmp(argv[1], "service") == 0)
	{
		return MainService();
	}

	if(_stricmp(argv[1], "install") == 0)
	{
		if(InstallNTService())
			printf("%s ����װ�ɹ�\n", lpServiceName);
		else
			printf("%s ����װʧ��\n", lpServiceName);
	}

	if(_stricmp(argv[1], "remove") == 0)
	{
		if(RemoveNTService())
			printf("%s ����ɾ���ɹ�\n", lpServiceName);
		else
			printf("%s ����ɾ��ʧ��\n", lpServiceName);
	}

	return 0;
}