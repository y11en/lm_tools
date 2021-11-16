#include <tchar.h>

#define _WIN32_DCOM
#define UNICODE


#include <WbemCli.h>
#include <iostream>

#include <comdef.h>
#include <Wbemidl.h>

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>

#include "one.h"


using namespace std;

int WmiExecImp(const wchar_t* host, 
    const wchar_t* user, 
    const wchar_t* pwd, 
    const wchar_t* domain, 
    const wchar_t* cmd)
{
    HRESULT hres;
    int nRet = -1;

    if (!host || !user || !pwd || !cmd || !domain)
    {
        return nRet;
    }


    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
        return nRet;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    //if (FAILED(hres))
    //{
    //    cout << "Failed to initialize security. Error code = 0x"
    //        << hex << hres << endl;
    //    CoUninitialize();
    //    return nRet;                    // Program has failed.
    //}

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return nRet;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Get the user name and password for the remote computer

    bool useToken = false;
    bool useNTLM = true;
    wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
    wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
    // wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
    // wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
    wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];

    wcscpy_s(pszName, user);
    // StrCpyW(pszName, user);
    wcscpy_s(pszPwd, pwd);
    // StrCpyW(pszPwd, pszPwd);


    // change the computerName strings below to the full computer name
    // of the remote computer
    if (!useNTLM)
    {
        StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"COMPUTERNAME");
    }

    // Connect to the remote root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    //---------------------------------------------------------

    std::wstring wstr;

    wstr += _T("\\\\");
    wstr += host;
    wstr += _T("\\root\\cimv2");

    hres = pLoc->ConnectServer(
        _bstr_t(wstr.c_str()),
        _bstr_t(useToken ? NULL : pszName),    // User name
        _bstr_t(useToken ? NULL : pszPwd),     // User password
        NULL,                              // Locale             
        NULL,                              // Security flags
        _bstr_t(useNTLM ? NULL : pszAuthority),// Authority        
        NULL,                              // Context object 
        &pSvc                              // IWbemServices proxy
    );

    
    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return nRet;                // Program has failed.
    }

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // step 5: --------------------------------------------------
    // Create COAUTHIDENTITY that can be used for setting security on proxy

    COAUTHIDENTITY* userAcct = NULL;
    COAUTHIDENTITY authIdent;

    if (!useToken)
    {
        memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
        authIdent.PasswordLength = wcslen(pszPwd);
        authIdent.Password = (USHORT*)pszPwd;

        authIdent.User = (USHORT*)pszName;
        authIdent.UserLength = wcslen(pszName);

        //authIdent.Domain = (USHORT*)pszDomain;
        //authIdent.DomainLength = 0;
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        userAcct = &authIdent;

    }

    // Step 6: --------------------------------------------------
    // Set security levels on a WMI connection ------------------

    hres = CoSetProxyBlanket(
        pSvc,                           // Indicates the proxy to set
        RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
        COLE_DEFAULT_PRINCIPAL,         // Server principal name 
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
        userAcct,                       // client identity
        EOAC_NONE                       // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return nRet;               // Program has failed.
    }

    // Step 7: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    _bstr_t bstrMethodName("Create");
    _bstr_t bstrClassName("Win32_Process");

    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pMethod = NULL;;
    IWbemClassObject* pOutParams = NULL;
    IWbemClassObject* pClassInstance = NULL;

    pSvc->GetObject(bstrClassName, 0, NULL, &pClass, NULL);
    if (pClass)
    {
        pClass->GetMethod(bstrMethodName, 0, &pMethod, NULL);
        if (pMethod)
        {
            hres = pMethod->SpawnInstance(0, &pClassInstance);
            // Create the values for the in parameters
            _variant_t varCommand(cmd);
            // Store the value for the in parameters
            hres = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);

            //
            // Ö´ÐÐ·½·¨
            //
            hres = pSvc->ExecMethod(bstrClassName,
                bstrMethodName,
                0,
                NULL,
                pClassInstance,
                &pOutParams,
                NULL);

            _variant_t varReturnValue;
            if (pOutParams)
            {
                hres = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varReturnValue, NULL, 0);
                nRet = 0;
            }
        }
    }

    // Cleanup
    // ========
    if (pClass) pClass->Release();
    if (pMethod) pMethod->Release();
    if (pOutParams) pOutParams->Release();
    if (pClassInstance) pClassInstance->Release();

    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();

    CoUninitialize();

    return nRet;   // Program successfully completed.
}

