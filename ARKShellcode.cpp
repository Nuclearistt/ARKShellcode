#include <WinSDKVer.h>
#define _WIN32_WINNT 0x0601 //Win7 compatibility
#include <SDKDDKVer.h>
//Don't include unnecessary APIs
#define WIN32_LEAN_AND_MEAN
#define NOGDICAPMASKS
#define NOVIRTUALKEYCODES
#define NOWINMESSAGES
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NOSYSCOMMANDS
#define NORASTEROPS
#define NOSHOWWINDOW
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOCTLMGR
#define NODRAWTEXT
#define NOGDI
#define NOKERNEL
#define NOUSER
#define NOMB
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOMSG
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#include <Windows.h>
#include <cwchar>

//Util function
template<typename T> constexpr inline T* ImageOffset(_In_ HMODULE baseAddress, _In_ DWORD offset)
{
	return reinterpret_cast<T*>(reinterpret_cast<BYTE*>(baseAddress) + offset);
}

//Steam API type definitions
typedef DWORD ServerQueryHandle;
typedef const void* ServerListRequestHandle;
enum class Result
{
	Ok = 1,
	Fail
};
struct MatchmakingKeyValuePair
{
	CHAR Key[256];
	CHAR Value[256];
};
struct SteamInterface //Generic representation of a C++ interface
{
	const void* const* VirtualMethodTable;
};
struct SubscribeResult
{
	Result ResultCode;
	DWORD64 ModId;
};

//Shellcode type definitions
enum class GameStatus
{
	NotOwned, //User account doesn't own ARK or user chose to use Spacewar, app ID is set to 480
	Owned, //User account owns ARK, app ID is set to 346110
	OwnedAndInstalled, //Steam also recognizes current game installation as its own
};
struct ModDownloadStartRequest
{
	DWORD Opcode;
	DWORD64 ModId;
};
struct ModDownloadProgress
{
	DWORD64 Current;
	DWORD64 Total;
	bool Complete;
};
struct StatusMessage
{
	DWORD Opcode;
	DWORD StatusCode;
};
struct SteamInterfaceWrapper
{
	const void* const* VirtualMethodTable; //Redirects to SteamApiInterface all functions that are not overridden
	SteamInterface* SteamApiInterface; //Wrapped interface pointer
	const void* VirtualMethodTableData[31]; //Every element should point to the according entry in RedirectFunctions unless overridden; 31 is the largest number of functions out of wrapped interfaces (ISteamUGC)
#pragma code_seg(push, ".text")
	//Contains 31 16-byte blocks of the following code:
	//	mov rcx, qword ptr [rcx+8] ;Set SteamApiInterface as the first parameter
	//	mov rax, qword ptr [rcx] ;Load original interace's virtual method table
	//	jmp qword ptr [rax+n] ;n is the index of method in the table multiplied by 8
	//	int3 padding until the end of 16-byte block
	__declspec(allocate(".text")) constexpr static BYTE RedirectFunctions[0x1F0]
	{
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x20, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x08, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x10, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x18, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x20, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x28, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x30, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x38, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x40, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x48, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x50, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x58, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x60, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x70, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x60, 0x78, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0x80, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0x88, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0x90, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0x98, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xA0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xA8, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xB0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xB8, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xC0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xC8, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xD0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xD8, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xE0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xE8, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC,
		0x48, 0x8B, 0x49, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0xA0, 0xF0, 0x00, 0x00, 0x00, 0xCC, 0xCC, 0xCC
	};
#pragma code_seg(pop)
	constexpr inline void Initialize(_In_ SteamInterface* originalInterface)
	{
		SteamApiInterface = originalInterface;
		VirtualMethodTable = VirtualMethodTableData;
		for (DWORD i = 0; i < 31; ++i)
			VirtualMethodTableData[i] = RedirectFunctions + i * 0x10;
	}
};
//Global SteamInterfaceWrapper objects
SteamInterfaceWrapper SteamAppsWrapper;
SteamInterfaceWrapper SteamMatchmakingServersWrapper;
SteamInterfaceWrapper SteamUGCWrapper;
SteamInterfaceWrapper SteamUtilsWrapper;
//Global Status declared before ServerRulesCallbackWrapper
GameStatus Status;

struct ServerRulesCallbackWrapper
{
	const void* const* VirtualMethodTable;
	SteamInterface* OriginalCallback;
	ServerQueryHandle QueryHandle;
	static const void* VirtualMethodTableData[3];
	static void RulesResponded(_In_ ServerRulesCallbackWrapper* wrapper, _In_ PCSTR rule, _In_ PCSTR value)
	{
		const size_t ruleLength = strlen(rule), valueLength = strlen(value);
		bool fail = ruleLength == 20 && *reinterpret_cast<const DWORD64*>(rule + 10) == 0x4559454C54544142 && valueLength != 5; //~rule.Length == "SERVERUSESBATTLEYE_b".Length && rule[10..18] == "BATLLEYE" && value.Length != "false".Length
		if (Status == GameStatus::NotOwned)
			fail |= ruleLength == 16 && *reinterpret_cast<const DWORD64*>(rule) == 0x454B484352414553 && (valueLength < 12 || *reinterpret_cast<const DWORD64*>(value) != 0x70706172574B4554); //~rule.Length == "SEARCHKEYWORDS_s".Length && rule.StartsWith("SEARCHKE") && !value.StartsWith("TEKWrapp")
		if (fail)
		{
			SteamInterface* const originalCallback = wrapper->OriginalCallback;
			wrapper->OriginalCallback = nullptr;
			reinterpret_cast<void(*)(SteamInterface*, ServerQueryHandle)>(SteamMatchmakingServersWrapper.SteamApiInterface->VirtualMethodTable[16])(SteamMatchmakingServersWrapper.SteamApiInterface, wrapper->QueryHandle);
			reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[1])(originalCallback);
		}
		else
			reinterpret_cast<void(*)(SteamInterface*, PCSTR, PCSTR)>(wrapper->OriginalCallback->VirtualMethodTable[0])(wrapper->OriginalCallback, rule, value);
	}
	static void RulesFailedToRespond(_In_ ServerRulesCallbackWrapper* wrapper)
	{
		SteamInterface* const originalCallback = wrapper->OriginalCallback;
		wrapper->OriginalCallback = nullptr;
		reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[1])(originalCallback);
	}
	static void RulesRefreshComplete(_In_ ServerRulesCallbackWrapper* wrapper)
	{
		SteamInterface* const originalCallback = wrapper->OriginalCallback;
		wrapper->OriginalCallback = nullptr;
		reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[2])(originalCallback);
	}
};
const void* ServerRulesCallbackWrapper::VirtualMethodTableData[3];

//Globals
WCHAR SteamApiPath[MAX_PATH];
DWORD64 SteamId;
PVOID Share;
HANDLE InputEvent;
HANDLE OutputEvent;
ServerRulesCallbackWrapper CallbackWrappers[256];
WCHAR ModsDirectorySearchPath[MAX_PATH];
size_t ModsDirectorySearchPathSize;
DWORD64 DownloadingModId;
bool ModDownloadInProgress;
DWORD64 InstalledMods[200];

//Steam API replacement functions
bool ReturnTrue() //Replaces 3 ownership check methods that return a bool
{
	return true;
}
_Post_equal_to_(steamId) DWORD64* GetAppOwner(_In_ SteamInterfaceWrapper* iSteamAppsWrapper, _Out_ DWORD64* steamId) //Implies that the game is not shared via Family Sharing
{
	*steamId = SteamId;
	return steamId;
}
ServerListRequestHandle RequestInternetServerList(_In_ SteamInterfaceWrapper* iSteamMatchmakingServersWrapper, _In_ DWORD appId, _In_reads_(numFilters) MatchmakingKeyValuePair** filters, _In_ DWORD numFilters, _In_ PVOID responseCallback) //Modifies filter string to search only servers that are not BattlEye-protected and, if Status is NotOwned, use TEK Wrapper
{
	char* cur = (*filters)[numFilters - 1].Value;
	//Make cur point to terminating null
	while (*cur)
		++cur;
	memcpy(cur, ",SERVERUSESBATTLEYE_b:false", 28);
	if (Status == GameStatus::NotOwned)
		memcpy(cur + 27, ",TEKWrapper:1", 14);
	return reinterpret_cast<ServerListRequestHandle(*)(SteamInterface*, DWORD, MatchmakingKeyValuePair**, DWORD, PVOID)>(iSteamMatchmakingServersWrapper->SteamApiInterface->VirtualMethodTable[0])(iSteamMatchmakingServersWrapper->SteamApiInterface, 346110, filters, numFilters, responseCallback);
}
ServerQueryHandle ServerRules(_In_ SteamInterfaceWrapper* iSteamMatchmakingServersWrapper, _In_ DWORD ip, _In_ WORD port, _In_ SteamInterface* responseCallback) //Wraps responseCallback
{
	ServerRulesCallbackWrapper* wrapper = CallbackWrappers;
	while (wrapper->OriginalCallback)
		++wrapper;
	wrapper->OriginalCallback = responseCallback;
	const ServerQueryHandle query = reinterpret_cast<ServerQueryHandle(*)(SteamInterface*, DWORD, WORD, ServerRulesCallbackWrapper*)>(iSteamMatchmakingServersWrapper->SteamApiInterface->VirtualMethodTable[15])(iSteamMatchmakingServersWrapper->SteamApiInterface, ip, port, wrapper);
	wrapper->QueryHandle = query;
	return query;
}
DWORD64 SubscribeItem(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ DWORD64 modId) //Instead of registering actual API call sends request to TEK Launcher and returns requested mod ID as unique identifier for other methods
{
	DownloadingModId = modId;
	*reinterpret_cast<ModDownloadStartRequest*>(Share) = { 1, modId };
	SetEvent(InputEvent);
	if (!WaitForSingleObject(OutputEvent, 500))
		ModDownloadInProgress = true;
	return modId;
}
DWORD GetNumSubscribedItems() //Counts all mod folders in Mods directory and also fills InstalledMods array with their IDs for further use in GetSubscribedItems()
{
	WIN32_FIND_DATAW findData;
	const HANDLE find = FindFirstFileExW(ModsDirectorySearchPath, FindExInfoBasic, &findData, FindExSearchLimitToDirectories, NULL, FIND_FIRST_EX_LARGE_FETCH);
	if (find == INVALID_HANDLE_VALUE)
		return 0;
	DWORD numInstalledMods = 0;
	FindNextFileW(find, &findData); //Skip .. entry
	while (FindNextFileW(find, &findData))
	{
		bool validNumber = true;
		DWORD64 id = 0;
		for (PCWSTR i = findData.cFileName; *i; ++i)
		{
			const DWORD64 digit = static_cast<DWORD64>(*i) - 48;
			if (digit > 9)
			{
				validNumber = false;
				break;
			}
			id = id * 10 + digit;
		}
		if (validNumber)
			InstalledMods[numInstalledMods++] = id;
	}
	FindClose(find);
	return numInstalledMods + static_cast<DWORD>(ModDownloadInProgress);
}
DWORD GetSubscribedItems(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _Out_writes_all_(numMods) DWORD64* modIds, _In_ DWORD numMods) //Simply copies InstalledMods into modIds
{
	numMods -= static_cast<DWORD>(ModDownloadInProgress);
	memcpy(modIds, InstalledMods, numMods * sizeof(DWORD64));
	if (ModDownloadInProgress)
		modIds[numMods++] = DownloadingModId;
	return numMods;
}
#pragma warning(suppress: 6054)
bool GetItemInstallInfo(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ DWORD64 modId, _Out_ DWORD64& sizeOnDisk, _Out_writes_z_(folderPathSize) PSTR folderPath, _In_ DWORD folderPathSize, _Out_ bool& isLegacyItem) //Converts mod ID into its folder path and checks if it exists
{
	sizeOnDisk = 0; //This is not used by the game so not worth computing
	isLegacyItem = false;
	WCHAR pathBuffer[MAX_PATH];
	memcpy(pathBuffer, ModsDirectorySearchPath, ModsDirectorySearchPathSize - 2);
	WCHAR numberBuffer[20] {};
	const PWSTR numberBufferEnd = numberBuffer + 20;
	PWSTR i = numberBufferEnd - 1;
	while (modId)
	{
		*--i = L'0' + (modId % 10);
		modId /= 10;
	}
	memcpy(pathBuffer + (ModsDirectorySearchPathSize - 2) / sizeof(WCHAR), i, (numberBufferEnd - i) * sizeof(WCHAR));
#pragma warning (suppress: 6054)
	if (GetFileAttributesW(pathBuffer) == INVALID_FILE_ATTRIBUTES)
	{
		*folderPath = '\0';
		return false;
	}
	else
	{
		WideCharToMultiByte(CP_UTF8, 0, pathBuffer, -1, folderPath, folderPathSize, NULL, NULL);
		return true;
	}
}
bool GetItemUpdateInfo(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ DWORD64 modId, _Out_ bool& needsUpdate, _Out_ bool& isDownloading, _Out_ DWORD64& bytesDownloaded, _Out_ DWORD64& bytesTotal) //Queries mod download progress from the launcher if possible
{
	if (ModDownloadInProgress && modId == DownloadingModId)
	{
		*reinterpret_cast<DWORD*>(Share) = 2; //Get mod download progress opcode
		SetEvent(InputEvent);
		if (!WaitForSingleObject(OutputEvent, 100))
		{
			const ModDownloadProgress* progress = reinterpret_cast<const ModDownloadProgress*>(Share);
			if (progress->Complete)
			{
				DownloadingModId = 0;
				ModDownloadInProgress = false;
			}
			else
			{
				isDownloading = needsUpdate = true;
				bytesDownloaded = progress->Current;
				bytesTotal = progress->Total;
				return true;
			}
		}
	}
	isDownloading = needsUpdate = false;
	bytesTotal = bytesDownloaded = 0;
	return false;
}
DWORD GetAppID()
{
	return 346110;
}
bool IsAPICallCompleted(_In_ SteamInterfaceWrapper* iSteamUtilsWrapper, _In_ DWORD64 apiCall, _Out_ bool& failed) //Tells that mod "subscribe" pseudo-call is complete
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		return true;
	}
	return reinterpret_cast<bool(*)(SteamInterface*, DWORD64, bool&)>(iSteamUtilsWrapper->SteamApiInterface->VirtualMethodTable[11])(iSteamUtilsWrapper->SteamApiInterface, apiCall, failed);
}
bool GetAPICallResult(_In_ SteamInterfaceWrapper* iSteamUtilsWrapper, _In_ DWORD64 apiCall, _Out_writes_bytes_(callbackSize) PVOID callback, _In_ DWORD callbackSize, _In_ DWORD callbackIndex, _Out_ bool& failed) //Returns mod "subscribe" pseudo-call result based on TEK Launcher response
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		*reinterpret_cast<SubscribeResult*>(callback) = { static_cast<Result>(static_cast<DWORD>(Result::Ok) + !ModDownloadInProgress), DownloadingModId };
		return true;
	}
	return reinterpret_cast<bool(*)(SteamInterface*, DWORD64, PVOID, DWORD, DWORD, bool&)>(iSteamUtilsWrapper->SteamApiInterface->VirtualMethodTable[13])(iSteamUtilsWrapper->SteamApiInterface, apiCall, callback, callbackSize, callbackIndex, failed);
}
//Shellcode entry point
void __declspec(noreturn) ShellcodeMain(_In_ void(*realEntryPoint)(DWORD64)) //Game process entry function, opens launcher's IPC objects, loads and wraps Steam API and proceeds to ShooterGame.exe entry point
{
	//Open TEK Launcher IPC objects
	const HANDLE shareMapping = OpenFileMappingW(FILE_MAP_WRITE | FILE_MAP_READ, FALSE, L"TEKLauncherShare");
	if (!shareMapping)
		ExitProcess(0);
	Share = MapViewOfFile(shareMapping, FILE_MAP_WRITE, 0, 0, 0x1000);
	CloseHandle(shareMapping);
	if (!Share)
		ExitProcess(0);
	InputEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"TEKLauncherInput");
	if (!InputEvent)
	{
		UnmapViewOfFile(Share);
		ExitProcess(0);
	}
	OutputEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, L"TEKLauncherOutput");
	if (!OutputEvent)
	{
		CloseHandle(InputEvent);
		UnmapViewOfFile(Share);
		ExitProcess(0);
	}
	//Load steam_api64.dll
	const HMODULE steamApiBase = LoadLibraryExW(SteamApiPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!steamApiBase)
	{
		*reinterpret_cast<StatusMessage*>(Share) = { 0, 7 };
		SetEvent(InputEvent);
		ExitProcess(0);
	}
	//Set Steam app ID accordingly to Status
	const LPCWSTR appId = Status == GameStatus::NotOwned ? L"480" : L"346110";
	SetEnvironmentVariableW(L"SteamAppId", appId);
	SetEnvironmentVariableW(L"GameAppId", appId);
	//Call SteamAPI_Init; ARK never updates steam_api64.dll so absolute offsets into image can be used
	if (!reinterpret_cast<bool(*)()>(ImageOffset<void>(steamApiBase, 0x51F0))())
	{
		*reinterpret_cast<StatusMessage*>(Share) = { 0, 8 };
		SetEvent(InputEvent);
		ExitProcess(0);
	}
	//Wrap Steam API interfaces and redirect methods
	SteamAppsWrapper.Initialize(*ImageOffset<SteamInterface*>(steamApiBase, 0x2FE98));
	*ImageOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FE98) = &SteamAppsWrapper;
	SteamAppsWrapper.VirtualMethodTableData[0] = ReturnTrue;
	SteamAppsWrapper.VirtualMethodTableData[6] = ReturnTrue;
	SteamAppsWrapper.VirtualMethodTableData[7] = ReturnTrue;
	SteamAppsWrapper.VirtualMethodTableData[20] = GetAppOwner;
	ServerRulesCallbackWrapper::VirtualMethodTableData[0] = ServerRulesCallbackWrapper::RulesResponded;
	ServerRulesCallbackWrapper::VirtualMethodTableData[1] = ServerRulesCallbackWrapper::RulesFailedToRespond;
	ServerRulesCallbackWrapper::VirtualMethodTableData[2] = ServerRulesCallbackWrapper::RulesRefreshComplete;
	ServerRulesCallbackWrapper* const callbackWrappersEnd = CallbackWrappers + 256;
	for (ServerRulesCallbackWrapper* i = CallbackWrappers; i < callbackWrappersEnd; ++i)
		i->VirtualMethodTable = ServerRulesCallbackWrapper::VirtualMethodTableData;
	SteamMatchmakingServersWrapper.Initialize(*ImageOffset<SteamInterface*>(steamApiBase, 0x2FEA0));
	*ImageOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FEA0) = &SteamMatchmakingServersWrapper;
	SteamMatchmakingServersWrapper.VirtualMethodTableData[0] = RequestInternetServerList;
	SteamMatchmakingServersWrapper.VirtualMethodTableData[15] = ServerRules;
	if (Status != GameStatus::OwnedAndInstalled)
	{
		SteamUGCWrapper.Initialize(*ImageOffset<SteamInterface*>(steamApiBase, 0x2FED8));
		*ImageOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FED8) = &SteamUGCWrapper;
		SteamUGCWrapper.VirtualMethodTableData[25] = SubscribeItem;
		SteamUGCWrapper.VirtualMethodTableData[27] = GetNumSubscribedItems;
		SteamUGCWrapper.VirtualMethodTableData[28] = GetSubscribedItems;
		SteamUGCWrapper.VirtualMethodTableData[29] = GetItemInstallInfo;
		SteamUGCWrapper.VirtualMethodTableData[30] = GetItemUpdateInfo;
		SteamUtilsWrapper.Initialize(*ImageOffset<SteamInterface*>(steamApiBase, 0x2FE80));
		*ImageOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FE80) = &SteamUtilsWrapper;
		if (Status == GameStatus::NotOwned)
			SteamUtilsWrapper.VirtualMethodTableData[9] = GetAppID;
		SteamUtilsWrapper.VirtualMethodTableData[11] = IsAPICallCompleted;
		SteamUtilsWrapper.VirtualMethodTableData[13] = GetAPICallResult;
	}
	//Proceed to executing ShooterGame.exe real entry point with PEB as argument
	realEntryPoint(__readgsqword(0x60));
}

//Injector
struct InjectionParameters
{
	HMODULE ImageBase;
	SIZE_T ImageSize;
	LPCWSTR ExePath;
	LPWSTR CommandLine;
	LPCWSTR CurrentDirectory;
	LPCWSTR SteamApiPath;
	LPCWSTR ModsDirectorySearchPath;
	size_t ModsDirectorySearchPathSize;
	GameStatus Status;
	DWORD64 SteamId;
	bool ReduceIntegrityLevel;
	bool SetHighProcessPriority;
};
DWORD Inject(_In_ InjectionParameters& injParams) //Entry point called within host process, creates game process and injects shellcode image into it
{
	//Copy parameters that will be used inside game process into image space
	wcscpy_s(SteamApiPath, injParams.SteamApiPath);
	memcpy(ModsDirectorySearchPath, injParams.ModsDirectorySearchPath, ModsDirectorySearchPathSize = injParams.ModsDirectorySearchPathSize);
	Status = injParams.Status;
	SteamId = injParams.SteamId;
	//Create game process
	DWORD creationFlags = CREATE_SUSPENDED;
	if (injParams.SetHighProcessPriority)
		creationFlags |= HIGH_PRIORITY_CLASS;
	STARTUPINFOW startupInfo { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION procInfo;
	if (injParams.ReduceIntegrityLevel)
	{
		HANDLE token;
		OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, &token);
		HANDLE mediumIntegrityToken;
		BOOL result = DuplicateTokenEx(token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, NULL, SecurityImpersonation, TokenPrimary, &mediumIntegrityToken);
		CloseHandle(token);
		if (!result)
			return 1;
		DWORD sid[3] { 0x101, 0x10000000, SECURITY_MANDATORY_MEDIUM_RID }; //Medium integrity level SID
		TOKEN_MANDATORY_LABEL mandatoryLabel { { &sid, SE_GROUP_INTEGRITY } };
		if (!SetTokenInformation(mediumIntegrityToken, TokenIntegrityLevel, &mandatoryLabel, sizeof(TOKEN_MANDATORY_LABEL)))
		{
			CloseHandle(mediumIntegrityToken);
			return 2;
		}
		result = CreateProcessAsUserW(mediumIntegrityToken, injParams.ExePath, injParams.CommandLine, NULL, NULL, FALSE, creationFlags, NULL, injParams.CurrentDirectory, &startupInfo, &procInfo);
		CloseHandle(mediumIntegrityToken);
		if (!result)
			return 3;
	}
	else if (!CreateProcessW(injParams.ExePath, injParams.CommandLine, NULL, NULL, FALSE, creationFlags, NULL, injParams.CurrentDirectory, &startupInfo, &procInfo))
		return 3;
	//Inject shellcode image
	DWORD exitCode;
	const LPVOID imageRegion = VirtualAllocEx(procInfo.hProcess, NULL, injParams.ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!imageRegion)
	{
		exitCode = 4;
		goto Exit;
	}
	if (!WriteProcessMemory(procInfo.hProcess, imageRegion, injParams.ImageBase, injParams.ImageSize, nullptr))
	{
		exitCode = 5;
		goto Exit;
	}
	//Modify RtlUserThreadStart arguments to make it run ShellcodeMain()
	CONTEXT threadContext;
	threadContext.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(procInfo.hThread, &threadContext);
	threadContext.Rdx = threadContext.Rcx; //Set real entry point address as second argument (entry function argument)
	threadContext.Rcx = reinterpret_cast<DWORD64>(ShellcodeMain) - reinterpret_cast<DWORD64>(injParams.ImageBase) + reinterpret_cast<DWORD64>(imageRegion); //Set ShellcodeMain() address as first argument (address of entry function)
	if (!SetThreadContext(procInfo.hThread, &threadContext))
	{
		exitCode = 6;
		goto Exit;
	}
	ResumeThread(procInfo.hThread); //Begin thread execution
	exitCode = 0;
Exit:
	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);
	return exitCode;
}