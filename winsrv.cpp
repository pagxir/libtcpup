#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>

#define _T(a) a
#define SERVICE_NAME _T("PUNCH_NAT")

class ScHandleWrap {
    public:
	ScHandleWrap(SC_HANDLE handle = NULL): mHandle(handle) {
	}

	~ScHandleWrap() {
	    release();
	}

	SC_HANDLE get() {
	    return mHandle;
	}

	void release() {
	    CloseServiceHandle(mHandle);
	}

	operator = (SC_HANDLE handle) {
	    if (handle != mHandle)
		CloseServiceHandle(mHandle);
	    mHandle = handle;
	}

    private:
	SC_HANDLE mHandle;
};

void _winsrv_stop();
int _winsrv(int argc, char *argv[]);

static volatile DWORD lastStatus = SERVICE_RUNNING;
static volatile SERVICE_STATUS_HANDLE sshStatusHandle;

static BOOL UpdateStatus(SERVICE_STATUS_HANDLE handle, DWORD status)
{
    SERVICE_STATUS ssStatus;

    if (handle != 0) {
        memset(&ssStatus, 0, sizeof(ssStatus));
        ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        ssStatus.dwCurrentState = status;

        return SetServiceStatus(handle, &ssStatus);
    }

    return FALSE;
}

static void CALLBACK _ControlHandle(DWORD dwCtrlCode)
{
    switch (dwCtrlCode) 
    {
	case SERVICE_CONTROL_STOP:
	    UpdateStatus(sshStatusHandle, lastStatus = SERVICE_STOP_PENDING);
	    _winsrv_stop();
	    break;

#if 0
	case SERVICE_CONTROL_PAUSE:
	    UpdateStatus(sshStatusHandle, lastStatus = SERVICE_PAUSED);
	    break;

	case SERVICE_CONTROL_CONTINUE:
	    UpdateStatus(sshStatusHandle, lastStatus = SERVICE_RUNNING);
	    break;
#endif

	case SERVICE_CONTROL_INTERROGATE:
	    UpdateStatus(sshStatusHandle, lastStatus);
	    break;

	default:
#if 0
	    RT_ASSERT((dwCtrlCode == SERVICE_CONTROL_STOP || dwCtrlCode == SERVICE_CONTROL_INTERROGATE),
		    "Invaliadate Service Control Code");
#endif
	    break;
    }
}

static void CALLBACK service_main(DWORD dwArgc, LPTSTR *lpszArgv)
{
    sshStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, _ControlHandle);
    UpdateStatus(sshStatusHandle, lastStatus);

    if (dwArgc > 2) {
	srand(time(NULL));
	_winsrv(dwArgc, lpszArgv);
    }

    UpdateStatus(sshStatusHandle, lastStatus = SERVICE_STOPPED);
}

static bool TryInstall()
{
    BOOL success = FALSE;
    TCHAR exePath[512];
    ScHandleWrap mScm, mSrv;

    mScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT| SC_MANAGER_CREATE_SERVICE);
    if (mScm.get() == NULL) {
        goto release;
    }

    if (GetModuleFileName(NULL, exePath, _countof(exePath)) == 0) {
	goto release;
    }

    mSrv = CreateService(mScm.get(), SERVICE_NAME, SERVICE_NAME, 0,
            SERVICE_WIN32_OWN_PROCESS| SERVICE_INTERACTIVE_PROCESS,
            /* SERVICE_AUTO_START*/ SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, exePath, NULL, NULL, NULL, NULL, NULL);

    if (mSrv.get() == NULL && ERROR_SERVICE_EXISTS != GetLastError()) {
        goto release;
    }

    if (mSrv.get() == NULL) {
	Sleep(1000);
    }

    success = TRUE;
release:
    fprintf(stderr, "CreateService: %p %p LastError: %d\n", mSrv.get(), mScm.get(), GetLastError());
    return success;
}

int main(int argc, char *argv[])
{
    SERVICE_STATUS srvStatus;
    ScHandleWrap mScm, mSrv;
    BOOL started = 0, removed = 0, success = 0;
#if 1
    SERVICE_TABLE_ENTRY dispatchTable[] = {
        { SERVICE_NAME, service_main },
        { NULL, NULL }
    };

    if (argc == 1 && GetStdHandle(STD_INPUT_HANDLE) == NULL) {
        success = StartServiceCtrlDispatcher(dispatchTable);
        OutputDebugString(success? _T("StartServiceCtrlDispatcher Success"): _T("StartServiceCtrlDispatcher failed\r\n"));
        return 0;
    }
#endif

    if (strcmp(argv[1], "--debug") == 0) {
       _winsrv(argc -1, argv + 1);
       return 0;
    }

    LPCSTR * listArgs = new LPCSTR[argc -1];
    int do_restart = 0, no_delete = 0, no_stop = 0;

    for (int i = 0; i < argc -1; i ++) {
	if (strcmp(argv[i + 1], "--restart") == 0) {
	    do_restart = 1;
	} else if (strcmp(argv[i + 1], "--nodelete") == 0) {
	    no_delete = 1;
	} else if (strcmp(argv[i + 1], "--nostop") == 0) {
	    no_stop = 1;
	} else {
	    listArgs[i] = argv[i + 1];
	}
    }

    success = TryInstall();
    if (success == FALSE) {
        goto crash;
    }

    mScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (mScm.get() == NULL) {
        goto crash;
    }

    mSrv = OpenService(mScm.get(), SERVICE_NAME, DELETE| SERVICE_START| SERVICE_STOP| SERVICE_QUERY_STATUS);
    if (mSrv.get() == NULL) {
        goto crash;
    }

    if (do_restart && (QueryServiceStatus(mSrv.get(), &srvStatus) != FALSE) &&
            (srvStatus.dwCurrentState != SERVICE_STOPPED)) {
        ControlService(mSrv.get(), SERVICE_CONTROL_STOP, &srvStatus);
        Sleep(1000);
    }

    if ((QueryServiceStatus(mSrv.get(), &srvStatus) != FALSE) &&
            (srvStatus.dwCurrentState == SERVICE_STOPPED)) {
        started = StartService(mSrv.get(), argc -1, listArgs);
        Sleep(1000);
    }

    delete[] listArgs;

    char action[128];
    fprintf(stderr, "StartService: %d LastError: %d Handle: %p State: %x\n",
	    started, GetLastError(), mSrv.get(), srvStatus.dwCurrentState);
    while (scanf("%128s", action) == 1) {
	if (strcmp(action, "exit") == 0) {
	    break;
	}

	if (strcmp(action, "quit") == 0) {
	    break;
	}
    }

    if (!no_stop && (QueryServiceStatus(mSrv.get(), &srvStatus) != FALSE) &&
            (srvStatus.dwCurrentState != SERVICE_STOPPED)) {
        ControlService(mSrv.get(), SERVICE_CONTROL_STOP, &srvStatus);
        Sleep(1000);
    }

    if (!no_delete && (QueryServiceStatus(mSrv.get(), &srvStatus) != FALSE) &&
            (srvStatus.dwCurrentState == SERVICE_STOPPED)) {
	removed = DeleteService(mSrv.get());
        goto crash;
    }

crash:
    fprintf(stderr, "result: started=%d removed=%d\n", started, removed);
    return 0;
}

#if 0
/* g++ -Wl,-subsystem,windows -static */
int APIENTRY WinMain(HINSTANCE hInstance,
        HINSTANCE hPrevInstance,
        LPTSTR    lpCmdLine,
        int       nCmdShow)
{
    return 0;
}
#endif
