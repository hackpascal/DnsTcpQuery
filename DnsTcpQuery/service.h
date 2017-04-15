VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPTSTR *lpServiceArgVectors);
VOID WINAPI ServiceControlHandler(DWORD dwControl);
BOOL WINAPI DebugControlHandler(DWORD dwCtrlType);

bool MainDebug();
bool MainService();
bool InstallNTService();
bool RemoveNTService();

extern const LPTSTR lpServiceName;