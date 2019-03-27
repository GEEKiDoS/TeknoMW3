// steam_api_emu.cpp : Defines the entry point for the DLL application.
//
#include "stdafx.h"
#include "SDK\SteamclientAPI.h"
#include "SDK\SteamAPI.h"
#include "util.h"
#include "util_codehook.h"
#include "util_adv_log.h"
#include "util_ini.h"
#include "winsock2.h"
#include "steam_api_emu.h"
#include "steam_api_emu_misc.h"
#include "steam_api_emu_interfaces.h"
#include "game_patch_base.h"
#include "game_patch_base_coop.h"
#include "game_server_items.h"
#include "dw_stun_server.h"
#include "dw_online_files.h"
#pragma comment(lib, "WSOCK32.LIB")

#ifdef __cplusplus
extern "C"
#endif
void * _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

bool IsInited = false;

CCallbackBase* g_MatchMakingCallbacks[20] = {NULL};
CCallbackBase* g_ServerCallbacks[20] = {NULL};
CCallbackBase* g_SteamUserCallbacks[20] = {NULL};
ISteamMatchmakingServerListResponse* g_RequestServersResponse = NULL;

char g_TeknoGodzMW2_Nickname[128] = "null";
int g_AppID = 42690;
unsigned long g_TeknoGodzMW2_ConnectIpAddr = 0;
unsigned short g_TeknoGodzMW2_ConnectPort = 0;
bool g_TeknoGodzMW2_isPendingConnect = false;
bool g_RequestLANServerList = false;
bool g_isServerIPInitialized = false;
bool g_OnlineMode = false;
CSteamID  g_LobbySteamId;
BYTE * g_AppTicket = NULL;
bool g_LobbyPendingCreate = false;
CSteamID  g_UserSteamId_def = CSteamID( 0x840101, k_EUniversePublic, k_EAccountTypeIndividual );
CSteamID  g_UserSteamId = g_UserSteamId_def;
bool g_bEncryptedAppTicketRequested = false;
CSteamID  g_RemoteLobbySteamId = CSteamID( 0x840100, k_EChatInstanceFlagLobby, k_EUniversePublic, k_EAccountTypeChat );
CSteamID  g_DedicatedServerSteamId = CSteamID( 0x840401, k_EUniversePublic, k_EAccountTypeGameServer );
DWORD g_HWID_Bak[5];


void __cdecl TeknoGodzMW2_SetNickname( char* nickname )
{
	g_Logging.AddToLogFileA( "steam_emu.log", "TeknoGodzMW2_SetNickname %s", nickname );

	//HKEY hKey;

	//if (RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Valve\\Steam\\", &hKey ) == ERROR_SUCCESS)
	//{
	//	RegSetValueExA(hKey, "LastNickName", NULL, REG_SZ, (BYTE *)nickname, strlen(nickname));
	//}

	_snprintf(g_TeknoGodzMW2_Nickname, 128, nickname);

	PersonaStateChange_t persset;
	persset.m_nChangeFlags = k_EPersonaChangeName;
	persset.m_ulSteamID = g_UserSteamId.ConvertToUint64();

	if (g_SteamUserCallbacks[1] != NULL)
	{
		g_SteamUserCallbacks[1]->Run(&persset);
	}
	if (g_SteamUserCallbacks[2] != NULL)
	{
		g_SteamUserCallbacks[2]->Run(&persset);
	}

}

void __cdecl TeknoGodzMW2_SetPendingConnection( unsigned long ipaddr, unsigned short port )
{
	g_Logging.AddToLogFileA( "steam_emu.log", "TeknoGodzMW2_SetPendingConnection %d.%d.%d.%d:%d", ipaddr>>24, (ipaddr&0xff0000) >> 16, (ipaddr&0xff00)>>8, ipaddr&0xff, port );
	g_TeknoGodzMW2_ConnectIpAddr = ipaddr;
	g_TeknoGodzMW2_ConnectPort = port;
	g_TeknoGodzMW2_isPendingConnect = true;
}



#pragma optimize("", off)

bool IsSetupDone = false;
int __cdecl TeknoGodzMW2_SteamSetup()
{	//VU("TeknoGodzMW2_SteamSetup");

	if (!IsSetupDone)
	{
		IsSetupDone = true;
		HKEY hKey;
		DWORD dwType = 0;
		DWORD dwSize = 0;
		DWORD steamIdDw = 0;
		char nickName[255];
		char tempid[255];
		memset(nickName, 0, 255);

		//init floating point operations
		InitFloat();


		CIniReader iniReader(V(".\\teknogods.ini"));
		CIniWriter iniWriter(V(".\\teknogods.ini"));

		char *name = iniReader.ReadString(V("Settings"),V("Name"),"");
		char *id = iniReader.ReadString(V("Settings"),V("ID"),"");
		g_NewFov = iniReader.ReadInteger(V("Settings"),V("FOV"), 0);
		g_TkDev = iniReader.ReadBoolean(V("Settings"),V("tkdev"), false);
		
		g_DefaultInterface = iniReader.ReadInteger(V("Network"),V("NetworkInterface"), 255);
		if (g_DefaultInterface == 255) iniWriter.WriteInteger(V("Network"),V("NetworkInterface"), 255);

		g_GlobalBans = iniReader.ReadBoolean(V("Network"),V("GlobalBans"), false);
		g_OnlineMode = iniReader.ReadBoolean(V("Network"),V("OnlineMode"), true);
		info("OnlineMode = %d", g_OnlineMode);


		//save all interfaces to ini file -- as extra info for people
		string ip_list = V("[");
		for (int i = 0; i < g_IpList.iAddressCount; i++)
		{
			const sockaddr_in *addr = (sockaddr_in *)g_IpList.Address[i].lpSockaddr;
			char ip_item[256];
			sprintf(ip_item, V("%d = %s; "), i, inet_ntoa(addr->sin_addr));
			ip_list = ip_list + ip_item;
		}
		ip_list = ip_list + V("255 (default) = ANY IP]");
		iniWriter.WriteString(V("Network"), V("NetworkInterfaceList"), (char *)ip_list.c_str()); 

		//other ip stuff
		char *lan_ip = iniReader.ReadString(V("Network"),V("ExternalIP"), "");
		if (strcmp(lan_ip, "") == 0) lan_ip = NULL;

		if (GAME_MODE == 'D' || lan_ip != NULL)
		{
			GetExternalIP(false, lan_ip);
		}
		else
		{
			//get lan ip
			DWORD int_ip = GetInternalIP();
			if (int_ip == 0) int_ip = GetHWIDSteamID();

			SetExternalIP(int_ip);
		}



		//master server stuff
		if (g_OnlineMode)
		{
			char *master = iniReader.ReadString(V("Network"),V("MasterServer"), V("mw3master.teknogods.com:27017"));
			
			if (!parseIpPort(master, &g_MasterIp, &g_MasterPort))
			{
				info("Failed to set the master-server port and ip (%s).", master);
			}
			else
			{
				char ips[255];
				makeIPstr(g_MasterIp, ips); 
				info("Master-server address set to: %s:%d.", ips, g_MasterPort);
			}
		}



		//dedicated server doesnt need special SteamID, so lets make it stay with the default one.
		if (GAME_MODE != 'D')
		{
			if(strcmp(id, "") == 0)
			{
				steamIdDw = GetHWIDSteamID();
				wsprintfA(tempid, V("%08X"),steamIdDw);
				iniWriter.WriteString(V("Settings"), V("ID"),tempid);
			}
			else
			{
				if (!charToDword(id, &steamIdDw))
				{
					iniWriter.WriteString(V("Errors"), V("LastError"), V("Your ID was incorrect (must be hex chars [0-9 a-f]), so we re-set it to HWID."));
					steamIdDw = GetHWIDSteamID();
					wsprintfA(tempid, V("%08X"),steamIdDw);
					iniWriter.WriteString(V("Settings"), V("ID"),tempid);
				}
			}

			//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			//steamIdDw = GetHWIDSteamID() ^ GetCurrentProcessId();

			g_UserSteamId = CSteamID( steamIdDw, k_EUniversePublic, k_EAccountTypeIndividual );
		}
		else
		{
			//dedicated server doesnt need any specific steam id or name.
			steamIdDw = GetHWIDSteamID() ^ GetCurrentProcessId();
			g_UserSteamId = CSteamID( steamIdDw, k_EUniversePublic, k_EAccountTypeGameServer );
			g_DedicatedServerSteamId = g_UserSteamId;
			sprintf(nickName, V("HostUser_%08X"), steamIdDw);
			name = nickName;
		}

		if(strcmp(name,"") != 0)
		{
			// Name is not empty
			TeknoGodzMW2_SetNickname(name);
		}
		else if (RegOpenKeyExA(HKEY_CURRENT_USER, V("Software\\Valve\\Steam\\"), 0L, KEY_READ, &hKey ) == ERROR_SUCCESS)
		{
			dwSize = 255;

			if (RegQueryValueExA(hKey, V("LastGameNameUsed"), NULL, &dwType, (BYTE *)nickName, &dwSize) == ERROR_SUCCESS)
			{
				_snprintf(g_TeknoGodzMW2_Nickname, 128, nickName);
				iniWriter.WriteString(V("Settings"),V("Name"),nickName);
			}
			else
			{

				char nickName[100];
				DWORD nnickName = sizeof(nickName);
				if (GetUserNameA((char*)nickName, &nnickName))
				{
					TeknoGodzMW2_SetNickname(nickName);
					iniWriter.WriteString(V("Settings"),V("Name"),nickName);
				}
				else
				{
					TeknoGodzMW2_SetNickname(V("^3TeknoSlave"));
					iniWriter.WriteString(V("Settings"), V("Name"), V("^3TeknoSlave"));
				}				
			}

			RegCloseKey(hKey);
		}
		else
		{
			CIniWriter iniWriter(V(".\\teknogods.ini"));
			TeknoGodzMW2_SetNickname(V("^3TeknoSlave"));
			iniWriter.WriteString(V("Settings"),V("Name"), V("^3TeknoSlave"));
		}




		#ifdef DEBUGGING_ENABLED
		char dbgout[255];
		sprintf_s(dbgout, 255, "TeknoGodzMW2_SteamSetup done. Name: %s, SteamID: 0x%08X.", g_TeknoGodzMW2_Nickname, steamIdDw);
		g_Logging.AddToLogFileA( "steam_emu.log", dbgout );
		OutputDebugStringA(dbgout);
		#endif
	}
	return 1;
	//VE();
}





DWORD WINAPI ProfileDumper_thread(LPVOID lpParameter)
{	//VM();ProfileDumper_thread");

	int i = 0;
	while (1)
	{
		Sleep(100);
		i++;
		if (i == 5)
		{
			char * profname = SaveDWMpdataToFile(true);

			if (profname == NULL)
			{
				MessageBoxA(0, V("Profile couldn't be dumped! Please report your game version back to us."), V("Information"), MB_ICONERROR);
				ExitProcess(0);
			}

			DWORD steamID = g_SteamID_DW64[0];

			char message[255];
			sprintf(message, V("Done. Profile dumped to \"%s\".\n\nClick YES if you would like to modify \"teknogods.ini\" to use SteamID (%08X) linked to that profile."), profname, steamID);

			if (MessageBoxA(0, message, V("Information"), MB_ICONINFORMATION | MB_YESNO) == IDYES)
			{
				sprintf(message, V("%08X"), steamID);
				CIniWriter iniWriter(V(".\\teknogods.ini"));

				iniWriter.WriteString(V("Settings"),V("ID"), message);
			}
			ExitProcess(0);			
		}
	}

	//VE();
}


bool RunSteamDRMCheck()
{
	return true;
}

#pragma optimize("", on)

static BYTE originalCode[5];
static PBYTE originalEP = 0;

void Main_UnprotectModule(HMODULE hModule)
{
	PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);

	// unprotect the entire PE image
	SIZE_T size = ntHeader->OptionalHeader.SizeOfImage;
	DWORD oldProtect;
	VirtualProtect((LPVOID)hModule, size, PAGE_EXECUTE_READWRITE, &oldProtect);
}

void Main_DoInit()
{
	// unprotect our entire PE image
	HMODULE hModule;
	if (SUCCEEDED(GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)Main_DoInit, &hModule)))
	{
		Main_UnprotectModule(hModule);
	}

	if (*(DWORD*)0x401B40 == 0x5638EC83) //client 1.4!
	{
		char * cmdline = GetCommandLineA();
		IsInited = true;
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);

		GetGameMode();

		//get all available ip's
		EnumNetworkAdapters();

		TeknoGodzMW2_SteamSetup();
		GetConsole();

		g_Patch_DW_STUN_Server_port_and_hosts = true;
		StartStunServer();
		HookAuthorizeIP();
		GetGameBuildNum();

		HookGetServerInfo();
		HookGetAssetFunc();
		GetHeatmapCheckPtr();
		GetBlobLoader();

		if (strstr(cmdline, V("+unranked")) != NULL)
		{
			g_Set_Ranked_Games = false;
		}


		HookDWLogFunc();
		HookDWGetFile();
		HookGenerateSecurityKeys();
		HookConsole();
		HookDvarToStrForScripts();
		PatchVariousStuff();
		GetDvarAndFuncListPtrs();
		HookKeyboard();

		RunSteamDRMCheck();
	}

	// return to the original EP
	memcpy(originalEP, &originalCode, sizeof(originalCode));
	__asm jmp originalEP
}


void Main_SetSafeInit()
{
	// find the entry point for the executable process, set page access, and replace the EP
	HMODULE hModule = GetModuleHandle(NULL); // passing NULL should be safe even with the loader lock being held (according to ReactOS ldr.c)

	if (hModule)
	{
		PIMAGE_DOS_HEADER header = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + header->e_lfanew);

		Main_UnprotectModule(hModule);

		// back up original code
		PBYTE ep = (PBYTE)((DWORD)hModule + ntHeader->OptionalHeader.AddressOfEntryPoint);
		memcpy(originalCode, ep, sizeof(originalCode));

		// patch to call our EP
		int newEP = (int)Main_DoInit - ((int)ep + 5);
		ep[0] = 0xE9; // for some reason this doesn't work properly when run under the debugger
		memcpy(&ep[1], &newEP, 4);

		originalEP = ep;
	}
}


BOOL __stdcall DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		Main_UnprotectModule(GetModuleHandle(NULL));

		Main_SetSafeInit();
	}

	return true;
}