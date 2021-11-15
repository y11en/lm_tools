#pragma once

// @Author: y11en 
// @date: 2021/11/15


enum METHOD_DCOM
{
	EM_ShellWindows = 1,
	EM_ShellBrowserWindow = 2,
	EM_MMC20 = 3,

};


// DCOM 远程命令执行
int DComExecImp(
    const wchar_t* host,
    const wchar_t* user,
    const wchar_t* pwd,
    const wchar_t* domain,
    const wchar_t* exe,
    const wchar_t* arg, METHOD_DCOM method);


// 远程服务执行
int SrvExecImp(const char* host, const char* domain,
    const char* user, const char* pwd,
    const char* srvname, const char* payload);


// 远程 WMI 
int WmiExecImp(const wchar_t* host,
	const wchar_t* user,
    const wchar_t* pwd,
    const wchar_t* domain,
    const wchar_t* cmd);