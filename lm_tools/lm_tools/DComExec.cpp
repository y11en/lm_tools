// @Author: y11en 
// @date: 2021/11/15


#include <tchar.h>

#define _WIN32_DCOM
#define UNICODE

#include <WbemCli.h>
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#include <shlwapi.h>
#include <shlobj.h>
#include <comutil.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>
#include <vector>


#include "one.h"


typedef struct
{
    _bstr_t _v;
    int type;
}InvokeObject;

// 使 pProxy 可以远程访问
HRESULT EnableRemoteInterface(IUnknown* pProxy, const wchar_t* host,
    const wchar_t* user,
    const wchar_t* pwd,
    const wchar_t* domain)
{
    COAUTHIDENTITY authIdent;
    COAUTHIDENTITY* userAcct = NULL;
    {
        memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
        authIdent.PasswordLength = wcslen(pwd);
        authIdent.Password = (USHORT*)pwd;
        authIdent.User = (USHORT*)user;
        authIdent.UserLength = wcslen(user);
        authIdent.Domain = (USHORT*)domain;
        authIdent.DomainLength = wcslen(domain);
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
        userAcct = &authIdent;

    }

    return CoSetProxyBlanket(
        pProxy,                           // Indicates the proxy to set
        RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
        COLE_DEFAULT_PRINCIPAL,         // Server principal name 
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
        userAcct,                       // client identity
        EOAC_NONE                       // proxy capabilities 
    );
}


int DComExecImp(
    const wchar_t* host,
    const wchar_t* user,
    const wchar_t* pwd,
	const wchar_t* domain,
    const wchar_t* exe,
    const wchar_t* arg, METHOD_DCOM method)
{
    HRESULT hr;
    int i = 0;
    DISPPARAMS params2 = { 0 };
    VARIANT Ressult[10] = { 0 }; // 尽量大，反正时临时存放下

    DISPID PropertyID[1] = { 0 };
    BSTR bst;
    LPCLSID pClsid = NULL;
    IDispatch* pdsp = NULL, * pdspRoot = NULL;

    //_bstr_t bst_item("Item");
    //_bstr_t bst_doc("Document");
    //_bstr_t bst_app("Application");

    std::vector<InvokeObject> callList;


    // Step 1: --------------------------------------------------
   // Initialize COM. ------------------------------------------

    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hr = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication :RPC_C_AUTHN_LEVEL_DEFAULT
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  :RPC_C_IMP_LEVEL_IDENTIFY
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );

    // DCOM 的2种验证：https://stackoverflow.com/questions/6123301/how-does-impersonation-in-dcom-work
    // REF https://blog.csdn.net/oShuangYue12/article/details/84328797
    COAUTHIDENTITY cai = {
        (USHORT*)user,
        wcslen(user),
        (USHORT*)domain,
        wcslen(domain),
        (USHORT*)pwd,
        wcslen(pwd),
        SEC_WINNT_AUTH_IDENTITY_UNICODE
    };

    COAUTHINFO AuthInfo = {   /* Use default settings according to MSDN. */
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE,
        &cai, EOAC_NONE
    };

    COSERVERINFO ServerInfo = { 0 };
    MULTI_QI qi[1];

    qi[0].pIID = &IID_IDispatch;
    qi[0].pItf = NULL;
    qi[0].hr = S_OK;

    ServerInfo.dwReserved1 = 0;
    ServerInfo.dwReserved2 = 0;
    ServerInfo.pAuthInfo = &AuthInfo;
    ServerInfo.pwszName = (LPWSTR)host;

    // 一些GUID常量
    struct __declspec(uuid("49B2791A-B1AE-4C90-9B8E-E860BA07F889")) CLSID_MM20;
    // # ShellWindows CLSID(Windows 7, Windows 10, Windows Server 2012R2)
    struct __declspec(uuid("9BA05972-F6A8-11CF-A442-00A0C90A8F39")) _CLSID_ShellWindows;
    //  # ShellBrowserWindow CLSID (Windows 10, Windows Server 2012R2)
    struct __declspec(uuid("C08AFD90-F2A1-11D1-8455-00A0C91F3880")) _CLSID_ShellBrowserWindow;

    switch (method)
    {
    case EM_ShellWindows:
        pClsid = (LPCLSID) & __uuidof(_CLSID_ShellWindows);
        callList.push_back({ "Item" , DISPATCH_METHOD });
        callList.push_back({ "Document" , DISPATCH_PROPERTYGET });
        callList.push_back({ "Application", DISPATCH_PROPERTYGET });

        break;
    case EM_ShellBrowserWindow:
        pClsid = (LPCLSID) & __uuidof(_CLSID_ShellBrowserWindow);
        callList.push_back({ "Document" , DISPATCH_PROPERTYGET });
        callList.push_back({ "Application", DISPATCH_PROPERTYGET });

        break;
    case EM_MMC20:
        pClsid = (LPCLSID) & __uuidof(CLSID_MM20);
        callList.push_back({ "Document" , DISPATCH_PROPERTYGET });
        break;
    default:
        break;
    }

    if (NULL == pClsid) return E_INVALIDARG;
    // assert(NULL != pClsid);

    // 创建 DCOM
    hr = CoCreateInstanceEx(
        *pClsid,
        NULL,
        CLSCTX_REMOTE_SERVER,
        &ServerInfo,
        1,
        qi);

    pdsp = pdspRoot = (IDispatch*)qi[0].pItf;
    hr = qi[0].hr;

    while (SUCCEEDED(hr))
    {
        hr = EnableRemoteInterface(pdspRoot, host, user, pwd, domain);
        for (auto pObj : callList)
        {

            bst = pObj._v.GetBSTR();
            hr = pdsp->GetIDsOfNames(IID_NULL, &bst, 1, LOCALE_SYSTEM_DEFAULT, PropertyID);   // Item
            if (FAILED(hr)) break;

            hr = pdsp->Invoke(PropertyID[0],
                IID_NULL, LOCALE_USER_DEFAULT, pObj.type, &params2, &Ressult[i], NULL, NULL);
            if (FAILED(hr)) break;

            hr = EnableRemoteInterface(Ressult[i].pdispVal, host, user, pwd, domain);
            if (FAILED(hr)) break;

            pdsp = Ressult[i++].pdispVal;
        }
        if (method == EM_MMC20)
        {
            // Document.ActiveView.ExecuteShellCommand
            /*
                Sub ExecuteShellCommand( _
                          ByVal Command As String, _
                          ByVal Directory As String, _
                          ByVal Parameters As String, _
                          ByVal WindowState As String _
                )
            */
            hr = EnableRemoteInterface(pdsp, host, user, pwd, domain);
            if (FAILED(hr)) break;

            bstr_t s_ActiveView("ActiveView");
            bstr_t s_ExecuteShellCommand("ExecuteShellCommand");

            bst = s_ActiveView.GetBSTR();
            hr = pdsp->GetIDsOfNames(IID_NULL, &bst, 1, LOCALE_SYSTEM_DEFAULT, PropertyID);
            if (FAILED(hr)) break;

            hr = pdsp->Invoke(PropertyID[0],
                IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &params2,
                &Ressult[i], NULL, NULL);

            if (FAILED(hr)) break;

            pdsp = Ressult[i++].pdispVal;

            hr = EnableRemoteInterface(pdsp, host, user, pwd, domain);
            if (FAILED(hr)) break;

            bst = s_ExecuteShellCommand.GetBSTR();
            hr = pdsp->GetIDsOfNames(IID_NULL, &bst, 1, LOCALE_SYSTEM_DEFAULT, PropertyID);
            if (FAILED(hr)) break;

            _bstr_t bstrProcessName(exe);
            _bstr_t bstrArg(arg);

            params2.cArgs = 4;
            params2.rgvarg = new VARIANT[params2.cArgs];

            // 它这个参数和正常思路不一样，参数反向填值
            // exe
            params2.rgvarg[3].vt = VT_BSTR;
            params2.rgvarg[3].bstrVal = bstrProcessName;

            // dir
            params2.rgvarg[2].vt = VT_EMPTY;

            // arg
            params2.rgvarg[1].vt = VT_BSTR;
            params2.rgvarg[1].bstrVal = bstrArg;

            // how show?
            params2.rgvarg[0].vt = VT_EMPTY;

            hr = pdsp->Invoke(PropertyID[0],
                IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params2, &Ressult[i++], NULL, NULL);

            break;
        }
        else
        {
            hr = EnableRemoteInterface(pdsp, host, user, pwd, domain);
            if (FAILED(hr)) break;

            _bstr_t s_ShellExecute("ShellExecute");

            bst = s_ShellExecute.GetBSTR();
            hr = pdsp->GetIDsOfNames(IID_NULL, &bst, 1, LOCALE_SYSTEM_DEFAULT, PropertyID);
            if (FAILED(hr)) break;

            // call 
            memset(&params2, 0, sizeof(params2));
            params2.cArgs = 5;
            params2.rgvarg = new VARIANT[params2.cArgs];

            _bstr_t bstrProcessName(exe);
            _bstr_t bstrOperation("open");
            _bstr_t bstrArg(arg);

            // 它这个参数和正常思路不一样，参数反向填值
            // exe
            params2.rgvarg[4].vt = VT_BSTR;
            params2.rgvarg[4].bstrVal = bstrProcessName;

            // arg
            params2.rgvarg[3].vt = VT_BSTR;
            params2.rgvarg[3].bstrVal = bstrArg;

            // dir
            params2.rgvarg[2].vt = VT_EMPTY;
            // params2.rgvarg[2].bstrVal = bstrProcessDir;

            // opt
            params2.rgvarg[1].vt = VT_BSTR;
            params2.rgvarg[1].bstrVal = bstrOperation;

            // show?
            params2.rgvarg[0].vt = VT_EMPTY;

            // ShellExecute()
            hr = pdsp->Invoke(PropertyID[0],
                IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &params2, &Ressult[i++], NULL, NULL);

            break;
        }
        break;
    }

_Exit:
    // free
    //for (int i = 0; i < sizeof(Ressult) / sizeof(Ressult[0]); ++i)
    //{
    //    if (Ressult[i].pdispVal)
    //        Ressult[i].pdispVal->Release();
    //}

    //if (pdspRoot)
    //    pdspRoot->Release();

    if (params2.rgvarg)
        delete[] params2.rgvarg;

    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : -1;
}