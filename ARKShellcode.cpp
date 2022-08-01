#include <sal.h>

//Basic type definitions
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef long int32;
typedef unsigned long uint32;
typedef __int64 int64;
typedef unsigned __int64 uint64;
typedef void* ptr;
typedef const void* cptr;
typedef wchar_t wchar;
typedef _Null_terminated_ char* str;
typedef _Null_terminated_ const char* cstr;
typedef _Null_terminated_ wchar* wstr;
typedef _Null_terminated_ const wchar* cwstr;
enum class bool32
{
	False,
	True
};

//Pointer util functions
template<typename T> constexpr inline T* PtrAddOffset(_In_ ptr base, _In_ uint32 offset)
{
	return reinterpret_cast<T*>(reinterpret_cast<byte*>(base) + offset);
}
template<typename T> constexpr inline const T* PtrAddOffset(_In_ cptr base, _In_ uint32 offset)
{
	return reinterpret_cast<const T*>(reinterpret_cast<const byte*>(base) + offset);
}

//Windows API type definitions
typedef _Return_type_success_(return >= 0) int32 NtStatus;
typedef cptr Handle;
typedef ptr ModuleHandle;
const Handle CurrentProcess = reinterpret_cast<Handle>(-1);
enum class FileAttribute
{
	Directory = 0x10
};
constexpr inline uint32 operator &(_In_ FileAttribute left, _In_ FileAttribute right)
{
	return static_cast<uint32>(left) & static_cast<uint32>(right);
}
enum class FileInformationClass
{
	Names = 12
};
enum class FileOpenOption
{
	DirectoryFile = 0x1
};
enum class FileShare
{
	All = 7
};
enum class LoaderFlag
{
	UnchangedRefCount = 0x1
};
enum class MemoryInformationClass
{
	Basic
};
enum class ObjectAttribute
{
	None,
	CaseInsensitive = 0x40
};
enum class PageAllocationType
{
	None,
	Commit = 0x1000,
	Reserve = 0x2000
};
enum class PageProtection
{
	ReadWrite = 0x4
};
struct AnsiString
{
	uint16 Length;
	uint16 MaxLength;
	cstr Buffer;
};
struct UnicodeString
{
	uint16 Length;
	uint16 MaxLength;
	cwstr Buffer;
};
struct FileBasicInformation
{
	uint64 Unused[4];
	FileAttribute Attributes;
};
struct FileNamesInformation
{
	uint32 NextEntryOffset;
	uint32 Index;
	uint32 NameLength;
	_Field_size_bytes_full_(NameLength) const wchar Name[1];
};
struct IoStatusBlock
{
	NtStatus Status;
	uint64 Information;
};
struct MemoryBasicInformation
{
	ptr BaseAddress;
	ptr AllocationBase;
	PageProtection Protection;
	uint16 Unused1;
	uint64 RegionSize;
	uint32 Unused2[3];
};
_Struct_size_bytes_(Size) struct ObjectAttributes
{
	uint32 Size;
	Handle RootDirectory;
	const UnicodeString* ObjectName;
	ObjectAttribute Attributes;
	cptr SecurityDescriptor;
	cptr SecurityQualityOfService;
};
struct UserProcessParameters
{
	uint32 Unused[13];
	UnicodeString CurrentDirectoryPath;
};
struct PEB
{
	uint32 Unused[7];
	const UserProcessParameters* ProcessParameters;
};

extern "C"
{
	//Compiler intrinsics
	uint64 strlen(_In_ cstr string);
#pragma intrinsic(strlen)
	_At_buffer_(destination, i, count, _Post_satisfies_(destination[i] == source[i])) void __movsb(_Out_writes_all_(count) str destination, _In_reads_(count) cstr source, _In_ uint64 count);
#pragma intrinsic(__movsb)
	_At_buffer_(destination, i, count, _Post_satisfies_(destination[i] == source[i])) void __movsq(_Out_writes_all_(count) uint64* destination, _In_reads_(count) const uint64* source, _In_ uint64 count);
#pragma intrinsic(__movsq)
	_At_buffer_(destination, i, count, _Post_satisfies_(destination[i] == source[i])) void __movsw(_Out_writes_all_(count) wstr destination, _In_reads_(count) cwstr source, _In_ uint64 count);
#pragma intrinsic(__movsw)
	uint64 __readgsqword(_In_ uint32 offset);
#pragma intrinsic(__readgsqword)

	//Windows API function imports
	__declspec(dllimport) NtStatus __stdcall LdrGetDllHandleEx(_In_ LoaderFlag flags, _In_opt_ cwstr path, _Out_opt_ uint32* characteristics, _In_ const UnicodeString& name, _Out_ ModuleHandle& handle);
	__declspec(dllimport) NtStatus __stdcall LdrGetProcedureAddressForCaller(_In_ ModuleHandle handle, _In_ const AnsiString& name, _In_opt_ uint32 ordinal, _Out_ ptr* address, _In_opt_ uint32 flags, _In_opt_ cptr unknown);
	__declspec(dllimport) NtStatus __stdcall NtAllocateVirtualMemory(_In_ Handle process, _Inout_ _Pre_null_ _Post_writable_byte_size_(regionSize) ptr& baseAddress, _In_opt_ uint64 zeroBits, _Inout_ uint64& regionSize, _In_ PageAllocationType allocationType, _In_ PageProtection protection);
	__declspec(dllimport) NtStatus __stdcall NtClose(_Post_invalid_ Handle handle);
	__declspec(dllimport) NtStatus __stdcall NtDelayExecution(_In_ bool alertable, _In_opt_ const int64& interval);
	__declspec(dllimport) NtStatus __stdcall NtMapViewOfSection(_In_ Handle section, _In_ Handle process, _Inout_ _Pre_null_ _Post_writable_byte_size_(viewSize) ptr& baseAddress, _In_opt_ uint64 zeroBits, _In_opt_ uint64 commitSize, _Inout_opt_ uint64* offset, _Inout_ uint64& viewSize, _In_ uint32 inheritDisposition, _In_ PageAllocationType allocationType, _In_ PageProtection protection);
	__declspec(dllimport) NtStatus __stdcall NtOpenEvent(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes);
	__declspec(dllimport) NtStatus __stdcall NtOpenFile(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes, _Out_ IoStatusBlock& statusBlock, _In_ FileShare shareAccess, _In_ FileOpenOption openOptions);
	__declspec(dllimport) NtStatus __stdcall NtOpenSection(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes);
	__declspec(dllimport) NtStatus __stdcall NtProtectVirtualMemory(_In_ Handle process, _Inout_ _Pre_valid_ ptr& baseAddress, _Inout_ uint64& protectionSize, _In_ PageProtection newProtection, _Out_ PageProtection& oldProtection);
	__declspec(dllimport) NtStatus __stdcall NtQueryAttributesFile(_In_ const ObjectAttributes& attributes, _Out_ FileBasicInformation& information);
	__declspec(dllimport) NtStatus __stdcall NtQueryDirectoryFile(_In_ Handle file, _In_opt_ Handle eventHandle, _In_opt_ ptr apcRoutine, _In_opt_ ptr apcContext, _Out_ IoStatusBlock& statusBlock, _Out_writes_bytes_(informationSize) FileNamesInformation* information, _In_ uint64 informationSize, _In_ FileInformationClass informationClass, _In_ bool returnSingleEntry, _In_opt_ const UnicodeString* fileMask, _In_ bool restartScan);
	__declspec(dllimport) NtStatus __stdcall NtQueryVirtualMemory(_In_ Handle process, _In_ cptr address, _In_ MemoryInformationClass informationClass, _Out_ MemoryBasicInformation& information, _In_ uint64 informationSize, _Out_opt_ uint64* returnSize);
	__declspec(dllimport) NtStatus __stdcall NtSetEvent(_In_ Handle eventHandle, _Out_opt_ uint32* previousState);
	__declspec(dllimport) NtStatus __stdcall NtUnmapViewOfSection(_In_ Handle process, _In_ cptr baseAddress);
	__declspec(dllimport) NtStatus __stdcall NtWaitForSingleObject(_In_ Handle handle, _In_ bool alertable, _In_opt_ const int64& timeout);
	__declspec(dllimport) NtStatus __stdcall RtlUnicodeToUTF8N(_Out_writes_bytes_to_(destinationStringMaxSize, destinationStringSize) str destinationString, _In_ uint32 destinationStringMaxSize, _Out_ uint32& destinationStringSize, _In_reads_bytes_(sourceStringSize) cwstr sourceString, _In_ uint32 sourceStringSize);
	__declspec(dllimport) NtStatus __stdcall BaseGetNamedObjectDirectory(_Out_ Handle& directory);
}

//Steam API type definitions
typedef uint32 ServerQueryHandle;
typedef ptr ServerListRequestHandle;
enum class Result
{
	Ok = 1,
	Fail
};
struct MatchmakingKeyValuePair
{
	char Key[256];
	char Value[256];
};
struct SteamInterface
{
	ptr* VirtualMethodTable;
};
struct SubscribeResult
{
	Result ResultCode;
	uint64 ModId;
};

//Steam API method defintions
typedef SteamInterface* (*InterfaceGetter)();
typedef ServerListRequestHandle (*RequestInternetServerList_t)(_In_ SteamInterface* iSteamMatchmakingServers, _In_ uint32 appId, _In_ MatchmakingKeyValuePair** filters, _In_ uint32 numFilters, _In_ ptr responseCallback);
typedef ServerQueryHandle (*ServerRules_t)(_In_ SteamInterface* iSteamMatchmakingServers, _In_ uint32 ip, _In_ uint16 port, _In_ SteamInterface* responseCallback);
typedef void (*RulesResponded_t)(_In_ SteamInterface* callback, _In_ cstr rule, _In_ cstr value);
typedef void (*RulesFailedToRespond_t)(_In_ SteamInterface* callback);
typedef void (*CancelServerQuery_t)(_In_ SteamInterface* iSteamMatchmakingServers, _In_ ServerQueryHandle query);
typedef bool (*IsAPICallCompleted_t)(_In_ SteamInterface* iSteamUtils, _In_ uint64 apiCall, _Out_ bool& failed);
typedef bool (*GetAPICallResult_t)(_In_ SteamInterface* iSteamUtils, _In_ uint64 apiCall, _Out_writes_bytes_(callbackSize) ptr callback, _In_ uint32 callbackSize, _In_ uint32 expectedCallback, _Out_ bool& failed);

//Shellcode type definitions
enum class GameStatus
{
	NotOwned, //User account doesn't own ARK, app ID is set to 480
	Owned, //User account owns ARK, app ID is set to 346110
	OwnedAndInstalled //Steam also recognizes current game installation as its own
};
struct BufferPage //Efficient use of memory space
{
	SteamInterface* MatchmakingRulesResponseCallbacks[0x30];
	uint64 InstalledMods[0xD0];
	char ModsDirectoryPath[0x3FC];
	uint32 FileNamesBufferSize;
	_Field_size_bytes_full_(FileNamesBufferSize) byte FileNamesBuffer[0x400]; //May be extended further by committing reserved pages
};
struct ModDownloadProgress
{
	uint64 Current;
	uint64 Total;
	bool Complete;
};
struct ModDownloadStartRequest
{
	uint32 Opcode;
	uint64 ModId;
};
struct PayloadData
{
	ptr WinApiFunctionPointers[18];
	//Original Steam API method pointers
	RequestInternetServerList_t RequestInternetServerList_o;
	ServerRules_t ServerRules_o;
	RulesResponded_t RulesResponded_o;
	IsAPICallCompleted_t IsAPICallCompleted_o;
	GetAPICallResult_t GetAPICallResult_o;
	//Strings
	UnicodeString SteamApiDllName; //{ 30, 32, SteamApiDllNameData }
	UnicodeString TekLauncherShareName; //{ 32, 34, TekLauncherShareNameData }
	UnicodeString TekLauncherInputName; //{ 32, 34, TekLauncherInputNameData }
	UnicodeString TekLauncherOutputName; //{ 34, 36, TekLauncherOutputNameData }
	AnsiString SteamAppsName; //{ 9, 10, SteamAppsNameData }
	AnsiString SteamMatchmakingServersName; //{ 23, 24, SteamMatchmakingServersNameData }
	AnsiString SteamUGCName; //{ 8, 9, payloadBase + SteamUGCNameData }
	AnsiString SteamUtilsName; //{ 10, 11, SteamUtilsNameData }
	wchar SteamApiDllNameData[16]; //{ L"steam_api64.dll" }
	wchar TekLauncherShareNameData[17]; //{ L"TEKLauncherShare" }
	wchar TekLauncherInputNameData[17]; //{ L"TEKLauncherInput" }
	wchar TekLauncherOutputNameData[18]; //{ L"TEKLauncherOutput" }
	char SteamAppsNameData[10]; //{ "SteamApps" }
	char SteamMatchmakingServersNameData[24]; //{ "SteamMatchmakingServers" }
	char SteamUGCNameData[9]; //{ "SteamUGC" }
	char SteamUtilsNameData[11]; //{ "SteamUtils" }
	//Global variables
	uint64 SteamId;
	BufferPage* Buffer;
	SteamInterface* ISteamMatchmakingServers;
	Handle ModsDirectoryHandle;
	uint32 ModsDirectoryPathLength;
	bool32 ModDownloadInProgress;
	uint64 DownloadingModId;
	struct IPC
	{
		ptr ShareView;
		Handle InputEvent;
		Handle OutputEvent;
	} Ipc;
};

//Global mocks (displacements in machine instructions referencing these will be changed later to point to their counterparts in PayloadData)
//Original Steam API method pointers
RequestInternetServerList_t RequestInternetServerList_o;
ServerRules_t ServerRules_o;
RulesResponded_t RulesResponded_o;
IsAPICallCompleted_t IsAPICallCompleted_o;
GetAPICallResult_t GetAPICallResult_o;
//Strings
UnicodeString SteamApiDllName;
UnicodeString TekLauncherShareName;
UnicodeString TekLauncherInputName;
UnicodeString TekLauncherOutputName;
AnsiString SteamAppsName;
AnsiString SteamMatchmakingServersName;
AnsiString SteamUGCName;
AnsiString SteamUtilsName;
//Global variables
uint64 SteamId;
BufferPage* Buffer;
SteamInterface* ISteamMatchmakingServers;
Handle ModsDirectoryHandle;
uint32 ModsDirectoryPathLength;
bool32 ModDownloadInProgress;
uint64 DownloadingModId;
PayloadData::IPC Ipc;

//Shellcode functions
bool ReturnTrue() { return true; } //Replaces 3 ownership check methods that return a bool
_Post_equal_to_(steamId) uint64* GetAppOwner(_In_ SteamInterface* iSteamApps, _Out_ uint64* steamId) //Implies that the game is not shared via Family Sharing
{
	*steamId = SteamId;
	return steamId;
}
ServerListRequestHandle RequestInternetServerList(_In_ SteamInterface* iSteamMatchmakingServers, _In_ uint32 appId, _In_ MatchmakingKeyValuePair** filters, _In_ uint32 numFilters, _In_ ptr responseCallback) //Modifies filter string to search only servers that use TEK Wrapper
{
	char* cur = (*filters)[numFilters - 1].Value;
	//Make cur point to terminating null
	while (*cur)
		++cur;
	*reinterpret_cast<uint64*>(cur) = 0x706172574B45542C; //",TEKWrap"
	*reinterpret_cast<uint32*>(cur += 8) = 0x3A726570; //"per:"
	*reinterpret_cast<uint16*>(cur += 4) = 0x0031; //"1\0"
	return RequestInternetServerList_o(iSteamMatchmakingServers, 346110, filters, numFilters, responseCallback);
}
void RulesResponded(_In_ SteamInterface* callback, _In_ cstr rule, _In_ cstr value) //Makes query fail if SEARCHKEYWORDS_s' value doesn't indicate that TEK Wrapper is used
{
	//~ if (rule.Length == "SEARCHKEYWORDS_s".Length && rule.StartsWith("SEARCHKE") && !value.StartsWith("TEKWrapp"))
	if (strlen(rule) == 16 && *reinterpret_cast<const uint64*>(rule) == 0x454B484352414553 && (strlen(value) < 12 || *reinterpret_cast<const uint64*>(value) != 0x70706172574B4554))
	{
		for (SteamInterface* const * i = Buffer->MatchmakingRulesResponseCallbacks; ; ++i)
			if (*i == callback)
			{
				reinterpret_cast<CancelServerQuery_t>(ISteamMatchmakingServers->VirtualMethodTable[16])(ISteamMatchmakingServers, static_cast<ServerQueryHandle>(i - Buffer->MatchmakingRulesResponseCallbacks));
				reinterpret_cast<RulesFailedToRespond_t>(callback->VirtualMethodTable[1])(callback);
				break;
			}
	}
	else
		RulesResponded_o(callback, rule, value);
}
ServerQueryHandle ServerRules(_In_ SteamInterface* iSteamMatchmakingServers, _In_ uint32 ip, _In_ uint16 port, _In_ SteamInterface* responseCallback) //Replaces RulesResponded callback unless it's done already and registers query in Buffer->MatchmakingRulesResponseCallbacksGlobal
{
	if (!RulesResponded_o)
	{
		ptr* virtualMethodTable = responseCallback->VirtualMethodTable;
		MemoryBasicInformation information;
		NtQueryVirtualMemory(CurrentProcess, virtualMethodTable, MemoryInformationClass::Basic, information, sizeof(MemoryBasicInformation), nullptr);
		PageProtection oldProtection;
		NtProtectVirtualMemory(CurrentProcess, information.BaseAddress, information.RegionSize, PageProtection::ReadWrite, oldProtection);
		RulesResponded_o = reinterpret_cast<RulesResponded_t>(virtualMethodTable[0]);
		virtualMethodTable[0] = RulesResponded;
		NtProtectVirtualMemory(CurrentProcess, information.BaseAddress, information.RegionSize, oldProtection, oldProtection);
	}
	const ServerQueryHandle query = ServerRules_o(iSteamMatchmakingServers, ip, port, responseCallback);
	//Clean up previous refernces to current response callback in the table since game reuses them
	SteamInterface** const currentResponseCallback = Buffer->MatchmakingRulesResponseCallbacks + query;
	for (SteamInterface** i = Buffer->MatchmakingRulesResponseCallbacks; i < currentResponseCallback; ++i)
		if (*i == responseCallback)
			*i = nullptr;
	*currentResponseCallback = responseCallback;
	return query;
}
uint64 SubscribeItem(_In_ SteamInterface* iSteamUGC, _In_ uint64 modId) //Instead of registering actual API call attempts to send request to TEK Launcher and returns requested mod ID as unique identifier for other methods
{
	ModDownloadInProgress = bool32::False;
	DownloadingModId = modId;
	Handle namedObjectsDir;
	BaseGetNamedObjectDirectory(namedObjectsDir);
	ObjectAttributes attributes{ sizeof(ObjectAttributes), namedObjectsDir, &TekLauncherShareName, ObjectAttribute::None, nullptr, nullptr };
	Handle shareSection;
	if (NtOpenSection(shareSection, 0x06, attributes))
		return modId;
	uint64 viewSize = 0;
	Ipc.ShareView = nullptr;
	NtMapViewOfSection(shareSection, CurrentProcess, Ipc.ShareView, 0, 0x1000, nullptr, viewSize, 2, PageAllocationType::None, PageProtection::ReadWrite);
	NtClose(shareSection); //View holds a reference to section so this handle is not needed anymore
	attributes.ObjectName = &TekLauncherInputName;
	NtOpenEvent(Ipc.InputEvent, 0x1F0003, attributes);
	attributes.ObjectName = &TekLauncherOutputName;
	NtOpenEvent(Ipc.OutputEvent, 0x1F0003, attributes);
	*reinterpret_cast<ModDownloadStartRequest*>(Ipc.ShareView) = { 0, modId };
	NtSetEvent(Ipc.InputEvent, nullptr);
	if (NtWaitForSingleObject(Ipc.OutputEvent, false, -5000000))
	{
		NtClose(Ipc.OutputEvent);
		NtClose(Ipc.InputEvent);
		NtUnmapViewOfSection(CurrentProcess, Ipc.ShareView);
	}
	else
		ModDownloadInProgress = bool32::True;
	return modId;
}
uint32 GetNumSubscribedItems() //Counts all mod folders in Mods directory and also fills InstalledMods array with their IDs for further use in GetSubscribedItems()
{
	IoStatusBlock statusBlock;
	BufferPage* buffer = Buffer;
	FileNamesInformation* directoryNames = reinterpret_cast<FileNamesInformation*>(buffer->FileNamesBuffer);
	uint32& fileNamesBufferSize = buffer->FileNamesBufferSize;
	uint64(&installedMods)[0xD0] = buffer->InstalledMods;
	const Handle modsDirectoryHandle = ModsDirectoryHandle;
	for (;;)
	{
		const NtStatus status = NtQueryDirectoryFile(modsDirectoryHandle, nullptr, nullptr, nullptr, statusBlock, directoryNames, fileNamesBufferSize, FileInformationClass::Names, false, nullptr, true);
		if (status == 0xC0000004) //STATUS_INFO_LENGTH_MISMATCH
		{
			if (fileNamesBufferSize == 0x2400) //No more memory to commit
				return 0;
			fileNamesBufferSize += 0x1000;
			uint64 newRegionSize = fileNamesBufferSize; //Will be rounded to next page boundary
			ptr baseAddress = buffer;
			if (NtAllocateVirtualMemory(CurrentProcess, baseAddress, 0, newRegionSize, PageAllocationType::Commit, PageProtection::ReadWrite))
				return 0;
			continue;
		}
		else if (status < 0)
			return 0;
		break;
	}
	if (NtWaitForSingleObject(modsDirectoryHandle, false, -2000000) || statusBlock.Status)
		return 0;
	uint32 numInstalledMods = 0;
	//Skip . and .. entries
	directoryNames = PtrAddOffset<FileNamesInformation>(directoryNames, directoryNames->NextEntryOffset);
	if (directoryNames->NextEntryOffset)
		do
		{
			directoryNames = PtrAddOffset<FileNamesInformation>(directoryNames, directoryNames->NextEntryOffset);
			const wchar* const nameEnd = PtrAddOffset<wchar>(directoryNames->Name, directoryNames->NameLength);
			bool validNumber = true;
			uint64 id = 0;
			for (const wchar* i = directoryNames->Name; i < nameEnd; ++i)
			{
				const uint64 digit = static_cast<uint64>(*i) - 48;
				if (digit > 9)
				{
					validNumber = false;
					break;
				}
				id = id * 10 + digit;
			}
			if (validNumber)
				installedMods[numInstalledMods++] = id;
		} while (directoryNames->NextEntryOffset);
	return numInstalledMods + static_cast<uint32>(ModDownloadInProgress);
}
uint32 GetSubscribedItems(_In_ SteamInterface* iSteamUGC, _In_ uint64* modIds, _In_ uint32 numMods) //Simply copies Buffer->InstalledMods into modIds
{
	numMods -= static_cast<uint32>(ModDownloadInProgress);
	__movsq(modIds, Buffer->InstalledMods, numMods);
	if (ModDownloadInProgress != bool32::False)
		modIds[numMods++] = DownloadingModId;
	return numMods;
}
bool GetItemInstallInfo(_In_ SteamInterface* iSteamUGC, _In_ uint64 modId, _Out_ uint64& sizeOnDisk, _Out_writes_z_(folderPathSize) str folderPath, _In_ uint32 folderPathSize, _Out_ bool& isLegacyItem) //Converts mod ID into its folder path and checks if it exists
{
	sizeOnDisk = 0; //This is not used by the game so not worth computing
	isLegacyItem = false;
	wchar buffer[20];
	wchar* const bufferEnd = buffer + 20;
	wchar* wcur = bufferEnd;
	while (modId)
	{
		*--wcur = L'0' + (modId % 10);
		modId /= 10;
	}
	const uint16 bufferSize = static_cast<uint16>(reinterpret_cast<const byte*>(bufferEnd) - reinterpret_cast<const byte*>(wcur));
	const UnicodeString folderName{ bufferSize, bufferSize, wcur };
	const ObjectAttributes attributes{ sizeof(ObjectAttributes), ModsDirectoryHandle, &folderName, ObjectAttribute::None, nullptr, nullptr };
	FileBasicInformation information;
	if (NtQueryAttributesFile(attributes, information) || !(information.Attributes & FileAttribute::Directory))
	{
		*folderPath = '\0';
		return false;
	}
	const uint32 modsDirectoryPathLength = ModsDirectoryPathLength;
	__movsb(folderPath, Buffer->ModsDirectoryPath, modsDirectoryPathLength);
	char* cur = folderPath + modsDirectoryPathLength;
	while (wcur < bufferEnd)
		*cur++ = static_cast<char>(*wcur++);
	*cur = '\0';
	return true;
}
bool GetItemUpdateInfo(_In_ SteamInterface* iSteamUGC, _In_ uint64 modId, _Out_ bool& needsUpdate, _Out_ bool& isDownloading, _Out_ uint64& bytesDownloaded, _Out_ uint64& bytesTotal) //Queries mod download progress from the launcher if possible
{
	if (ModDownloadInProgress != bool32::False && modId == DownloadingModId)
	{
		const ptr shareView = Ipc.ShareView;
		const Handle inputEvent = Ipc.InputEvent;
		const Handle outputEvent = Ipc.OutputEvent;
		*reinterpret_cast<uint32*>(shareView) = 1; //Get mod download progress opcode
		NtSetEvent(inputEvent, nullptr);
		if (!NtWaitForSingleObject(outputEvent, false, -1000000))
		{
			const ModDownloadProgress* progress = reinterpret_cast<const ModDownloadProgress*>(shareView);
			if (progress->Complete)
			{
				DownloadingModId = 0;
				ModDownloadInProgress = bool32::False;
				NtClose(outputEvent);
				NtClose(inputEvent);
				NtUnmapViewOfSection(CurrentProcess, shareView);
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
uint32 GetAppID() //Server list requests use return value of this method
{
	return 346110;
}
bool IsAPICallCompleted(_In_ SteamInterface* iSteamUtils, _In_ uint64 apiCall, _Out_ bool& failed) //Tells that mod "subscribe" pseudo-call is complete
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		return true;
	}
	return IsAPICallCompleted_o(iSteamUtils, apiCall, failed);
}
bool GetAPICallResult(_In_ SteamInterface* iSteamUtils, _In_ uint64 apiCall, _Out_writes_bytes_(callbackSize) ptr callback, _In_ uint32 callbackSize, _In_ uint32 expectedCallback, _Out_ bool& failed) //Returns mod "subscribe" pseudo-call result based on TEK Launcher response
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		*reinterpret_cast<SubscribeResult*>(callback) = { static_cast<Result>(static_cast<uint32>(Result::Ok) + (ModDownloadInProgress == bool32::False)), DownloadingModId };
		return true;
	}
	return GetAPICallResult_o(iSteamUtils, apiCall, callback, callbackSize, expectedCallback, failed);
}
uint32 __stdcall Main(_In_ GameStatus status) //Awaits Steam API initialization and modifies virtual method tables of certain interfaces to point to shellcode's functions
{
	if (status != GameStatus::OwnedAndInstalled)
	{
		//Reserve 3 pages for Buffer
		ptr baseAddress = nullptr;
		uint64 regionSize = 0x3000;
		if (NtAllocateVirtualMemory(CurrentProcess, baseAddress, 0, regionSize, PageAllocationType::Reserve, PageProtection::ReadWrite))
			return 0;
		//Commit 1 page
		regionSize = 0x1000;
		if (NtAllocateVirtualMemory(CurrentProcess, baseAddress, 0, regionSize, PageAllocationType::Commit, PageProtection::ReadWrite))
			return 0;
		BufferPage* const buffer = reinterpret_cast<BufferPage*>(baseAddress);
		buffer->FileNamesBufferSize = 0x400;
		Buffer = buffer;
		//Get mods directory handle and path
		const UnicodeString* currentDirectoryPath = &reinterpret_cast<PEB*>(__readgsqword(0x60))->ProcessParameters->CurrentDirectoryPath;
		wchar modsDirectoryPathData[264];
		*reinterpret_cast<uint64*>(modsDirectoryPathData) = 0x005C003F003F005C; //L"\\??\\"
		const uint64 baseLength = static_cast<uint64>(currentDirectoryPath->Length) / 2 - 27;
		wchar* cur = modsDirectoryPathData + 4;
		__movsw(cur, currentDirectoryPath->Buffer, baseLength);
		cur += baseLength;
		*reinterpret_cast<uint64*>(cur) = 0x00730064006F004D; //L"Mods"
		const UnicodeString modsDirectoryPath{ static_cast<uint16>(currentDirectoryPath->Length - 38), 528, modsDirectoryPathData };
		const ObjectAttributes attributes{ sizeof(ObjectAttributes), nullptr, &modsDirectoryPath, ObjectAttribute::CaseInsensitive, nullptr, nullptr };
		IoStatusBlock statusBlock;
		NtOpenFile(ModsDirectoryHandle, 0x100001, attributes, statusBlock, FileShare::All, FileOpenOption::DirectoryFile);
		uint32 modsDirectoryPathLength;
		RtlUnicodeToUTF8N(buffer->ModsDirectoryPath, 0x3FC, modsDirectoryPathLength, modsDirectoryPathData + 4, static_cast<uint32>(modsDirectoryPath.Length) - 8);
		buffer->ModsDirectoryPath[modsDirectoryPathLength] = '\\';
		ModsDirectoryPathLength = modsDirectoryPathLength + 1;
	}
	const int64 delay = -5000000; //Relative 500 ms
	ModuleHandle steamApiModule;
	while (LdrGetDllHandleEx(LoaderFlag::UnchangedRefCount, nullptr, nullptr, SteamApiDllName, steamApiModule))
		NtDelayExecution(false, delay); //Wait until steam_api64.dll is loaded
	InterfaceGetter getter;
	LdrGetProcedureAddressForCaller(steamApiModule, SteamAppsName, 0, reinterpret_cast<ptr*>(&getter), 0, nullptr);
	SteamInterface* iSteamApps;
	while(!(iSteamApps = getter()))
		NtDelayExecution(false, delay); //Wait until Steam API interfaces are initialized
	ptr* virtualMethodTable = iSteamApps->VirtualMethodTable;
	MemoryBasicInformation memoryInfo;
	NtQueryVirtualMemory(CurrentProcess, virtualMethodTable, MemoryInformationClass::Basic, memoryInfo, sizeof(MemoryBasicInformation), nullptr);
	PageProtection oldProtection;
	NtProtectVirtualMemory(CurrentProcess, memoryInfo.BaseAddress, memoryInfo.RegionSize, PageProtection::ReadWrite, oldProtection); //Make virtual method table memory region writable
	virtualMethodTable[0] = ReturnTrue; //BIsSubscribed
	virtualMethodTable[6] = ReturnTrue; //BIsSubscribedApp
	virtualMethodTable[7] = ReturnTrue; //BIsDlcInstalled
	virtualMethodTable[20] = GetAppOwner;
	if (status != GameStatus::OwnedAndInstalled)
	{
		if (status == GameStatus::NotOwned)
		{
			LdrGetProcedureAddressForCaller(steamApiModule, SteamMatchmakingServersName, 0, reinterpret_cast<ptr*>(&getter), 0, nullptr);
			ISteamMatchmakingServers = getter();
			virtualMethodTable = ISteamMatchmakingServers->VirtualMethodTable;
			RequestInternetServerList_o = reinterpret_cast<RequestInternetServerList_t>(virtualMethodTable[0]);
			ServerRules_o = reinterpret_cast<ServerRules_t>(virtualMethodTable[15]);
			virtualMethodTable[0] = RequestInternetServerList;
			virtualMethodTable[15] = ServerRules;
		}
		LdrGetProcedureAddressForCaller(steamApiModule, SteamUGCName, 0, reinterpret_cast<ptr*>(&getter), 0, nullptr);
		virtualMethodTable = getter()->VirtualMethodTable;
		virtualMethodTable[25] = SubscribeItem;
		virtualMethodTable[27] = GetNumSubscribedItems;
		virtualMethodTable[28] = GetSubscribedItems;
		virtualMethodTable[29] = GetItemInstallInfo;
		virtualMethodTable[30] = GetItemUpdateInfo;
		LdrGetProcedureAddressForCaller(steamApiModule, SteamUtilsName, 0, reinterpret_cast<ptr*>(&getter), 0, nullptr);
		virtualMethodTable = getter()->VirtualMethodTable;
		if (status == GameStatus::NotOwned)
			virtualMethodTable[9] = GetAppID;
		IsAPICallCompleted_o = reinterpret_cast<IsAPICallCompleted_t>(virtualMethodTable[11]);
		GetAPICallResult_o = reinterpret_cast<GetAPICallResult_t>(virtualMethodTable[13]);
		virtualMethodTable[11] = IsAPICallCompleted;
		virtualMethodTable[13] = GetAPICallResult;
	}
	NtProtectVirtualMemory(CurrentProcess, memoryInfo.BaseAddress, memoryInfo.RegionSize, oldProtection, oldProtection); //Restore old memory region protection
	return 0;
}