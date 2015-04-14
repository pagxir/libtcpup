#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <windows.h>

#define EVENT_NAME ("Global\\EPol_SDServer.Event")

static volatile DWORD lastStatus = SERVICE_RUNNING;
static volatile SERVICE_STATUS_HANDLE sshStatusHandle;

void _winsrv_stop();
int _winsrv(int argc, char *argv[]);

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

static void CALLBACK _Daemonize(DWORD dwArgc, LPTSTR *lpszArgv)
{
	static char *_winsrv_args[] = {"main.exe", "-l", "53", "127.0.0.1:3389"};
	sshStatusHandle = RegisterServiceCtrlHandler(("SAAgent"), _ControlHandle);
	UpdateStatus(sshStatusHandle, lastStatus);

	if (lpszArgv == NULL || dwArgc < 2) {
		_winsrv(4, _winsrv_args);
	} else {
		_winsrv(dwArgc, lpszArgv);
	}

	UpdateStatus(sshStatusHandle, lastStatus = SERVICE_STOPPED);
}

static SERVICE_TABLE_ENTRY _DispatchTable[] =
{
	{ TEXT("SAAgent"), _Daemonize },
	{ NULL, NULL }
};

int main(int argc, char *argv[])
{
	WSADATA data;
	BOOL bSuccess;

	while (argc > 1) {
		if (strcmp(argv[1], "--debug") == 0) {
			return 0;
		}

		if (strcmp(argv[1], "--ver") == 0) {
			fprintf(stderr, "source version: 2015-04-14\n");
			return 0;
		}

		if (strcmp(argv[1], "--version") == 0) {
			fprintf(stderr, "source version: 2015-04-14\n");
			return 0;
		}

		return 0;
	}

	srand(time(NULL));
	WSAStartup(0x101, &data);

	if (argc < 2) {

		bSuccess = StartServiceCtrlDispatcher(_DispatchTable);
		if (bSuccess == FALSE) {
			DWORD dwError = GetLastError();
			fprintf(stderr, "Service start failue: %d!\n", dwError);
			return dwError;
		}

		return 0;
	}

	WSACleanup();

	return 0;
}

