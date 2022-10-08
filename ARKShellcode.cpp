#include <sal.h>

//Basic type definitions
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef long int32;
typedef unsigned long uint32;
typedef __int64 int64;
typedef unsigned __int64 uint64;
typedef union __declspec(intrin_type) alignas(16) __m128i //Operations with this type use SSE instructions
{
	uint64 Halves[2];
} uint128;
typedef void* ptr;
typedef const void* cptr;
typedef wchar_t wchar;
typedef _Null_terminated_ char* str;
typedef _Null_terminated_ const char* cstr;
typedef _Null_terminated_ wchar* wstr;
typedef _Null_terminated_ const wchar* cwstr;

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
enum class CreateProcessParametersFlags
{
	Normalize = 0x1
};
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
	LoadWithAlteredSearchPath = 0x8
};
enum class ObjectAttribute
{
	None,
	CaseInsensitive = 0x40
};
enum class PageAllocationType
{
	None,
	ReserveAndCommit = 0x3000
};
enum class PageProtection
{
	ReadWrite = 0x4,
	ExecuteReadWrite = 0x40
};
enum class ProcessFlag
{
	None
};
enum class ProcessInformationClass
{
	BasePriority = 18
};
enum class ThreadFlag
{
	CreateSuspended = 0x1
};
enum class TokenInformationClass
{
	IntegrityLevel = 25
};
enum class TokenType
{
	Primary = 1
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
	uint32 NameSize;
	_Field_size_bytes_full_(NameSize) wchar Name[2];
};
struct IoStatusBlock
{
	NtStatus Status;
	uint64 Information;
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
struct PEB
{
	uint64 Unused[2];
	ModuleHandle BaseAddress;
};
struct ProcessAttribute
{
	uint64 Attribute;
	uint64 Size;
	cptr Value;
	uint64* ReturnSize;
};
_Struct_size_bytes_(TotalSize) struct ProcessAttributeList
{
	uint64 TotalSize;
	ProcessAttribute Attributes[2];
};
_Struct_size_bytes_(Size) struct ProcessCreateInformation
{
	uint64 Size;
	uint64 Unused[10];
};
struct TokenMandatoryLabel
{
	cptr Sid;
	uint32 Attributes;
};

extern "C"
{
	//Compiler intrinsics
	uint64 strlen(_In_ cstr string);
#pragma intrinsic(strlen)
	uint64 __readgsqword(_In_ uint32 offset);
#pragma intrinsic(__readgsqword)

	//Windows API function imports
	__declspec(dllimport) NtStatus LdrLoadDll(_In_ LoaderFlag flags, _In_opt_ uint32* reserved, _In_ const UnicodeString& filePath, _Out_ ModuleHandle& moduleHandle);
	__declspec(dllimport) NtStatus NtAllocateVirtualMemory(_In_ Handle process, _Inout_ _Pre_maybenull_ _Post_writable_byte_size_(regionSize) ptr& baseAddress, _In_ uint64 zeroBits, _Inout_ uint64& regionSize, _In_ PageAllocationType allocationType, _In_ PageProtection protection);
	__declspec(dllimport) NtStatus NtClose(_Post_invalid_ Handle handle);
	__declspec(dllimport) NtStatus NtCreateThreadEx(_Out_ Handle& handle, _In_ uint32 accessMask, _In_opt_ const ObjectAttributes* attributes, _In_ Handle process, _In_ cptr startRoutine, _In_opt_ cptr argument, _In_ uint32 flags, _In_ uint64 zeroBits, _In_ uint64 stackSize, _In_ uint64 maxStackSize, _In_opt_ ptr attributeList);
	__declspec(dllimport) NtStatus NtCreateUserProcess(_Out_ Handle& process, _Out_ Handle& thread, _In_ uint32 processAccessMask, _In_ uint32 ThreadAccessMask, _In_opt_ const ObjectAttributes* processAttributes, _In_opt_ const ObjectAttributes* threadAttributes, _In_ ProcessFlag processFlags, _In_ ThreadFlag threadFlags, _In_ cptr parameters, _In_ const ProcessCreateInformation& createInfo, _In_ const ProcessAttributeList& attributeList);
	__declspec(dllimport) NtStatus NtDuplicateToken(_In_ Handle token, _In_ uint32 accessMask, _In_opt_ const ObjectAttributes* attributes, _In_ bool effectiveOnly, _In_ TokenType type, _Out_ Handle& newToken);
	__declspec(dllimport) NtStatus NtMapViewOfSection(_In_ Handle section, _In_ Handle process, _Inout_ _Pre_maybenull_ _Post_writable_byte_size_(viewSize) ptr& baseAddress, _In_ uint64 zeroBits, _In_ uint64 commitSize, _Inout_opt_ int64* offset, _Inout_ uint64& viewSize, _In_ uint32 inheritDisposition, _In_ PageAllocationType allocationType, _In_ PageProtection protection);
	__declspec(dllimport) NtStatus NtOpenEvent(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes);
	__declspec(dllimport) NtStatus NtOpenFile(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes, _Out_ IoStatusBlock& statusBlock, _In_ FileShare shareAccess, _In_ FileOpenOption openOptions);
	__declspec(dllimport) NtStatus NtOpenProcessToken(_In_ Handle process, _In_ uint32 accessMask, _Out_ Handle& handle);
	__declspec(dllimport) NtStatus NtOpenSection(_Out_ Handle& handle, _In_ uint32 accessMask, _In_ const ObjectAttributes& attributes);
	__declspec(dllimport) NtStatus NtQueryAttributesFile(_In_ const ObjectAttributes& attributes, _Out_ FileBasicInformation& information);
	__declspec(dllimport) NtStatus NtQueryDirectoryFile(_In_ Handle file, _In_opt_ Handle eventHandle, _In_opt_ ptr apcRoutine, _In_opt_ ptr apcContext, _Out_ IoStatusBlock& statusBlock, _Out_writes_bytes_(informationSize) FileNamesInformation* information, _In_ uint64 informationSize, _In_ FileInformationClass informationClass, _In_ bool returnSingleEntry, _In_opt_ const UnicodeString* fileMask, _In_ bool restartScan);
	__declspec(dllimport) NtStatus NtSetEvent(_In_ Handle eventHandle, _Out_opt_ uint32* previousState);
	__declspec(dllimport) NtStatus NtSetInformationProcess(_In_ Handle process, _In_ ProcessInformationClass informationClass, _In_ const uint16& information, _In_ uint32 informationSize);
	__declspec(dllimport) NtStatus NtSetInformationToken(_In_ Handle token, _In_ TokenInformationClass informationClass, _In_ const TokenMandatoryLabel& information, _In_ uint32 informationSize);
	__declspec(dllimport) NtStatus NtTerminateThread(_In_ Handle thread, _In_ uint32 exitCode);
	__declspec(dllimport) NtStatus NtUnmapViewOfSection(_In_ Handle process, _Post_invalid_ cptr baseAddress);
	__declspec(dllimport) NtStatus NtWaitForSingleObject(_In_ Handle handle, _In_ bool alertable, _In_opt_ const int64* timeout);
	__declspec(dllimport) NtStatus NtWriteVirtualMemory(_In_ Handle process, _In_ ptr address, _In_ cptr buffer, _In_ uint32 bufferSize, _Out_opt_ uint32* bytesWritten);
	__declspec(dllimport) NtStatus RtlCreateProcessParametersEx(_Outref_ ptr& processParameters, _In_ const UnicodeString& imagePath, _In_opt_ const UnicodeString* dllPath, _In_ const UnicodeString& currentDirectory, _In_ const UnicodeString& commandLine, _In_opt_ cwstr environment, _In_opt_ const UnicodeString* windowTitle, _In_opt_ const UnicodeString* desktopInfo, _In_opt_ const UnicodeString* shellInfo, _In_opt_ const UnicodeString* runtimeData, _In_ CreateProcessParametersFlags flags);
	__declspec(dllimport) NtStatus RtlDestroyProcessParameters(_Post_invalid_ ptr processParameters);
	__declspec(dllimport) NtStatus RtlSetEnvironmentVar(_In_opt_ cwstr environment, _In_reads_(nameLength) cwstr name, _In_ uint64 nameLength, _In_reads_(valueLength) cwstr value, _In_ uint64 valueLength);
	_Post_equal_to_(destination) _At_buffer_((const byte*)destination, i, count, _Post_satisfies_(((const byte*)destination)[i] == ((const byte*)source)[i])) ptr memcpy(_Out_writes_bytes_all_(count) ptr destination, _In_reads_bytes_(count) cptr source, _In_ uint64 count);
	__declspec(dllimport) NtStatus BaseGetNamedObjectDirectory(_Out_ Handle& directory);
}

//Steam API type definitions
typedef uint32 ServerQueryHandle;
typedef cptr ServerListRequestHandle;
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
struct SteamInterface //Generic representation of a C++ interface
{
	cptr* VirtualMethodTable;
};
struct SubscribeResult
{
	Result ResultCode;
	uint64 ModId;
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
	uint32 Opcode;
	uint64 ModId;
};
struct ModDownloadProgress
{
	uint64 Current;
	uint64 Total;
	bool Complete;
};
struct StatusMessage
{
	uint32 Opcode;
	uint32 StatusCode;
};
struct SteamInterfaceWrapper
{
	cptr* VirtualMethodTable; //Redirects to SteamApiInterface all functions that are not overridden
	SteamInterface* SteamApiInterface; //Wrapped interface pointer
	cptr VirtualMethodTableData[31]; //Every element should point to the according entry in RedirectFunctions unless overridden; 31 is the largest number of functions out of wrapped interfaces (ISteamUGC)
#pragma code_seg(push, ".text")
	//Contains 31 16-byte blocks of the following code:
	//	mov rcx, qword ptr [rcx+8] ;Set SteamApiInterface as the first parameter
	//	mov rax, qword ptr [rcx] ;Load original interace's virtual method table
	//	jmp qword ptr [rax+n] ;n is the index of method in the table multiplied by 8
	//	int3 padding until the end of 16-byte block
	__declspec(allocate(".text")) constexpr static byte RedirectFunctions[0x1F0]
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
		for (uint32 i = 0; i < 31; ++i)
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
	const cptr* VirtualMethodTable;
	SteamInterface* OriginalCallback;
	ServerQueryHandle QueryHandle;
	static cptr VirtualMethodTableData[3];
	static void RulesResponded(ServerRulesCallbackWrapper* wrapper, cstr rule, cstr value)
	{
		const uint64 ruleLength = strlen(rule);
		const uint64 valueLength = strlen(value);
		bool fail = ruleLength == 20 && *reinterpret_cast<const uint64*>(rule + 10) == 0x4559454C54544142 && valueLength != 5; //~rule.Length == "SERVERUSESBATTLEYE_b".Length && rule[10..18] == "BATLLEYE" && value.Length != "false".Length
		if (Status == GameStatus::NotOwned)
			fail |= ruleLength == 16 && *reinterpret_cast<const uint64*>(rule) == 0x454B484352414553 && (valueLength < 12 || *reinterpret_cast<const uint64*>(value) != 0x70706172574B4554); //~rule.Length == "SEARCHKEYWORDS_s".Length && rule.StartsWith("SEARCHKE") && !value.StartsWith("TEKWrapp")
		if (fail)
		{
			SteamInterface* const originalCallback = wrapper->OriginalCallback;
			wrapper->OriginalCallback = nullptr;
			reinterpret_cast<void(*)(SteamInterface*, ServerQueryHandle)>(SteamMatchmakingServersWrapper.SteamApiInterface->VirtualMethodTable[16])(SteamMatchmakingServersWrapper.SteamApiInterface, wrapper->QueryHandle);
			reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[1])(originalCallback);
		}
		else
			reinterpret_cast<void(*)(SteamInterface*, cstr, cstr)>(wrapper->OriginalCallback->VirtualMethodTable[0])(wrapper->OriginalCallback, rule, value);
	}
	static void RulesFailedToRespond(ServerRulesCallbackWrapper* wrapper)
	{
		SteamInterface* const originalCallback = wrapper->OriginalCallback;
		wrapper->OriginalCallback = nullptr;
		reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[1])(originalCallback);
	}
	static void RulesRefreshComplete(ServerRulesCallbackWrapper* wrapper)
	{
		SteamInterface* const originalCallback = wrapper->OriginalCallback;
		wrapper->OriginalCallback = nullptr;
		reinterpret_cast<void(*)(SteamInterface*)>(originalCallback->VirtualMethodTable[2])(originalCallback);
	}
};
cptr ServerRulesCallbackWrapper::VirtualMethodTableData[3];

//Globals
wchar SteamApiPath[260];
uint32 SteamApiPathSize;
uint64 SteamId;
ptr Share;
Handle InputEvent;
Handle OutputEvent;
ServerRulesCallbackWrapper CallbackWrappers[256];
wchar ModsDirectoryPathUnicode[264];
uint32 ModsDirectoryPathUnicodeSize;
char ModsDirectoryPathUtf8[520];
uint32 ModsDirectoryPathUtf8Size;
Handle ModsDirectoryHandle;
uint64 DownloadingModId;
bool ModDownloadInProgress;
FileNamesInformation DirectoryNamesBuffer[0x200]; //0x2000 bytes total
uint64 InstalledMods[200];

//Steam API replacement functions
bool ReturnTrue() //Replaces 3 ownership check methods that return a bool
{
	return true;
}
_Post_equal_to_(steamId) uint64* GetAppOwner(_In_ SteamInterfaceWrapper* iSteamAppsWrapper, _Out_ uint64* steamId) //Implies that the game is not shared via Family Sharing
{
	*steamId = SteamId;
	return steamId;
}
ServerListRequestHandle RequestInternetServerList(_In_ SteamInterfaceWrapper* iSteamMatchmakingServersWrapper, _In_ uint32 appId, _In_reads_(numFilters) MatchmakingKeyValuePair** filters, _In_ uint32 numFilters, _In_ ptr responseCallback) //Modifies filter string to search only servers that are not BattlEye-protected and, if Status is NotOwned, use TEK Wrapper
{
	char* cur = (*filters)[numFilters - 1].Value;
	//Make cur point to terminating null
	while (*cur)
		++cur;
	memcpy(cur, ",SERVERUSESBATTLEYE_b:false", 28);
	if (Status == GameStatus::NotOwned)
		memcpy(cur + 27, ",TEKWrapper:1", 14);
	return reinterpret_cast<ServerListRequestHandle(*)(SteamInterface*, uint32, MatchmakingKeyValuePair**, uint32, ptr)>(iSteamMatchmakingServersWrapper->SteamApiInterface->VirtualMethodTable[0])(iSteamMatchmakingServersWrapper->SteamApiInterface, 346110, filters, numFilters, responseCallback);
}
ServerQueryHandle ServerRules(_In_ SteamInterfaceWrapper* iSteamMatchmakingServersWrapper, _In_ uint32 ip, _In_ uint16 port, _In_ SteamInterface* responseCallback) //Wraps responseCallback
{
	ServerRulesCallbackWrapper* wrapper = CallbackWrappers;
	while (wrapper->OriginalCallback)
		++wrapper;
	wrapper->OriginalCallback = responseCallback;
	const ServerQueryHandle query = reinterpret_cast<ServerQueryHandle(*)(SteamInterface*, uint32, uint16, ServerRulesCallbackWrapper*)>(iSteamMatchmakingServersWrapper->SteamApiInterface->VirtualMethodTable[15])(iSteamMatchmakingServersWrapper->SteamApiInterface, ip, port, wrapper);
	wrapper->QueryHandle = query;
	return query;
}
uint64 SubscribeItem(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ uint64 modId) //Instead of registering actual API call sends request to TEK Launcher and returns requested mod ID as unique identifier for other methods
{
	DownloadingModId = modId;
	*reinterpret_cast<ModDownloadStartRequest*>(Share) = { 1, modId };
	NtSetEvent(InputEvent, nullptr);
	const int64 timeout = -5000000;
	if (!NtWaitForSingleObject(OutputEvent, false, &timeout))
		ModDownloadInProgress = true;
	return modId;
}
uint32 GetNumSubscribedItems() //Counts all mod folders in Mods directory and also fills InstalledMods array with their IDs for further use in GetSubscribedItems()
{
	IoStatusBlock statusBlock;
	const int64 timeout = -2000000;
	if (NtQueryDirectoryFile(ModsDirectoryHandle, nullptr, nullptr, nullptr, statusBlock, DirectoryNamesBuffer, 0x2000, FileInformationClass::Names, false, nullptr, true) < 0 || NtWaitForSingleObject(ModsDirectoryHandle, false, &timeout) || statusBlock.Status)
		return 0;
	uint32 numInstalledMods = 0;
	//Skip . and .. entries
	const FileNamesInformation* directoryNames = PtrAddOffset<FileNamesInformation>(DirectoryNamesBuffer, DirectoryNamesBuffer->NextEntryOffset);
	if (directoryNames->NextEntryOffset)
		do
		{
			directoryNames = PtrAddOffset<FileNamesInformation>(directoryNames, directoryNames->NextEntryOffset);
			const wchar* const nameEnd = PtrAddOffset<wchar>(directoryNames->Name, directoryNames->NameSize);
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
				InstalledMods[numInstalledMods++] = id;
		} while (directoryNames->NextEntryOffset);
	return numInstalledMods + static_cast<uint32>(ModDownloadInProgress);
}
uint32 GetSubscribedItems(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _Out_writes_all_(numMods) uint64* modIds, _In_ uint32 numMods) //Simply copies InstalledMods into modIds
{
	numMods -= static_cast<uint32>(ModDownloadInProgress);
	for (uint32 i = 0; i < numMods / 2; ++i)
		reinterpret_cast<uint128*>(modIds)[i] = reinterpret_cast<const uint128*>(InstalledMods)[i];
	if (numMods & 1)
		modIds[numMods - 1] = InstalledMods[numMods - 1];
	if (ModDownloadInProgress)
		modIds[numMods++] = DownloadingModId;
	return numMods;
}
#pragma warning(suppress: 6054)
bool GetItemInstallInfo(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ uint64 modId, _Out_ uint64& sizeOnDisk, _Out_writes_z_(folderPathSize) str folderPath, _In_ uint32 folderPathSize, _Out_ bool& isLegacyItem) //Converts mod ID into its folder path and checks if it exists
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
	FileBasicInformation information;
	if (NtQueryAttributesFile({ sizeof(ObjectAttributes), ModsDirectoryHandle, &folderName, ObjectAttribute::None, nullptr, nullptr }, information) || !(information.Attributes & FileAttribute::Directory))
	{
		*folderPath = '\0';
		return false;
	}
	memcpy(folderPath, ModsDirectoryPathUtf8, ModsDirectoryPathUtf8Size);
	char* cur = folderPath + ModsDirectoryPathUtf8Size;
	while (wcur < bufferEnd)
		*cur++ = static_cast<char>(*wcur++);
	*cur = '\0';
	return true;
}
bool GetItemUpdateInfo(_In_ SteamInterfaceWrapper* iSteamUGCWrapper, _In_ uint64 modId, _Out_ bool& needsUpdate, _Out_ bool& isDownloading, _Out_ uint64& bytesDownloaded, _Out_ uint64& bytesTotal) //Queries mod download progress from the launcher if possible
{
	if (ModDownloadInProgress && modId == DownloadingModId)
	{
		*reinterpret_cast<uint32*>(Share) = 2; //Get mod download progress opcode
		NtSetEvent(InputEvent, nullptr);
		const int64 timeout = -1000000;
		if (!NtWaitForSingleObject(OutputEvent, false, &timeout))
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
uint32 GetAppID()
{
	return 346110;
}
bool IsAPICallCompleted(_In_ SteamInterfaceWrapper* iSteamUtilsWrapper, _In_ uint64 apiCall, _Out_ bool& failed) //Tells that mod "subscribe" pseudo-call is complete
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		return true;
	}
	return reinterpret_cast<bool(*)(SteamInterface*, uint64, bool&)>(iSteamUtilsWrapper->SteamApiInterface->VirtualMethodTable[11])(iSteamUtilsWrapper->SteamApiInterface, apiCall, failed);
}
bool GetAPICallResult(_In_ SteamInterfaceWrapper* iSteamUtilsWrapper, _In_ uint64 apiCall, _Out_writes_bytes_(callbackSize) ptr callback, _In_ uint32 callbackSize, _In_ uint32 callbackIndex, _Out_ bool& failed) //Returns mod "subscribe" pseudo-call result based on TEK Launcher response
{
	if (apiCall == DownloadingModId)
	{
		failed = false;
		*reinterpret_cast<SubscribeResult*>(callback) = { static_cast<Result>(static_cast<uint32>(Result::Ok) + !ModDownloadInProgress), DownloadingModId };
		return true;
	}
	return reinterpret_cast<bool(*)(SteamInterface*, uint64, ptr, uint32, uint32, bool&)>(iSteamUtilsWrapper->SteamApiInterface->VirtualMethodTable[13])(iSteamUtilsWrapper->SteamApiInterface, apiCall, callback, callbackSize, callbackIndex, failed);
}
//Shellcode entry point
uint32 ShellcodeMain() //Game process entry function, opens launcher's IPC objects, loads and wraps Steam API and proceeds to ShooterGame.exe entry point
{
	UnicodeString objectName{ 32, 34, L"TEKLauncherShare" };
	ObjectAttributes attributes{ sizeof(ObjectAttributes), nullptr, &objectName, ObjectAttribute::None, nullptr, nullptr };
	BaseGetNamedObjectDirectory(attributes.RootDirectory);
	Handle shareSection;
	if (NtOpenSection(shareSection, 0x06, attributes))
		return 0;
	uint64 viewSize = 0;
	const NtStatus status = NtMapViewOfSection(shareSection, CurrentProcess, Share, 0, 0x1000, nullptr, viewSize, 2, PageAllocationType::None, PageProtection::ReadWrite);
	NtClose(shareSection);
	if (status)
		return 0;
	objectName = { 32, 34, L"TEKLauncherInput" };
	if (NtOpenEvent(InputEvent, 0x1F0003, attributes))
	{
		NtUnmapViewOfSection(CurrentProcess, Share);
		return 0;
	}
	objectName = { 34, 36, L"TEKLauncherOutput" };
	if (NtOpenEvent(OutputEvent, 0x1F0003, attributes))
	{
		NtClose(InputEvent);
		NtUnmapViewOfSection(CurrentProcess, Share);
		return 0;
	}
	//Load steam_api64.dll
	ModuleHandle steamApiBase;
	if (LdrLoadDll(LoaderFlag::LoadWithAlteredSearchPath, nullptr, { static_cast<uint16>(SteamApiPathSize), static_cast<uint16>(SteamApiPathSize + 2), SteamApiPath }, steamApiBase))
	{
		*reinterpret_cast<StatusMessage*>(Share) = { 0, 7 };
		NtSetEvent(InputEvent, nullptr);
		return 0;
	}
	//Call SteamAPI_Init; ARK never updates steam_api64.dll so absolute offsets into image can be used
	if (!reinterpret_cast<bool(*)()>(PtrAddOffset<void>(steamApiBase, 0x51F0))())
	{
		*reinterpret_cast<StatusMessage*>(Share) = { 0, 8 };
		NtSetEvent(InputEvent, nullptr);
		return 0;
	}
	//Wrap Steam API interfaces and redirect methods
	SteamAppsWrapper.Initialize(*PtrAddOffset<SteamInterface*>(steamApiBase, 0x2FE98));
	*PtrAddOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FE98) = &SteamAppsWrapper;
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
	SteamMatchmakingServersWrapper.Initialize(*PtrAddOffset<SteamInterface*>(steamApiBase, 0x2FEA0));
	*PtrAddOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FEA0) = &SteamMatchmakingServersWrapper;
	SteamMatchmakingServersWrapper.VirtualMethodTableData[0] = RequestInternetServerList;
	SteamMatchmakingServersWrapper.VirtualMethodTableData[15] = ServerRules;
	if (Status != GameStatus::OwnedAndInstalled)
	{
		const UnicodeString modsDirectoryPath { static_cast<uint16>(ModsDirectoryPathUnicodeSize), 528, ModsDirectoryPathUnicode };
		IoStatusBlock statusBlock;
		if (NtOpenFile(ModsDirectoryHandle, 0x100001, { sizeof(ObjectAttributes), nullptr, &modsDirectoryPath, ObjectAttribute::CaseInsensitive, nullptr, nullptr }, statusBlock, FileShare::All, FileOpenOption::DirectoryFile))
		{
			*reinterpret_cast<StatusMessage*>(Share) = { 0, 9 };
			NtSetEvent(InputEvent, nullptr);
			return 0;
		}
		SteamUGCWrapper.Initialize(*PtrAddOffset<SteamInterface*>(steamApiBase, 0x2FED8));
		*PtrAddOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FED8) = &SteamUGCWrapper;
		SteamUGCWrapper.VirtualMethodTableData[25] = SubscribeItem;
		SteamUGCWrapper.VirtualMethodTableData[27] = GetNumSubscribedItems;
		SteamUGCWrapper.VirtualMethodTableData[28] = GetSubscribedItems;
		SteamUGCWrapper.VirtualMethodTableData[29] = GetItemInstallInfo;
		SteamUGCWrapper.VirtualMethodTableData[30] = GetItemUpdateInfo;
		SteamUtilsWrapper.Initialize(*PtrAddOffset<SteamInterface*>(steamApiBase, 0x2FE80));
		*PtrAddOffset<SteamInterfaceWrapper*>(steamApiBase, 0x2FE80) = &SteamUtilsWrapper;
		if (Status == GameStatus::NotOwned)
			SteamUtilsWrapper.VirtualMethodTableData[9] = GetAppID;
		SteamUtilsWrapper.VirtualMethodTableData[11] = IsAPICallCompleted;
		SteamUtilsWrapper.VirtualMethodTableData[13] = GetAPICallResult;
	}
	//Proceed to executing ShooterGame.exe entry point, essentially making current thread the main one
	PEB* const peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
	const ModuleHandle imageBase = peb->BaseAddress;
	reinterpret_cast<void(*)(PEB*)>(PtrAddOffset<void>(imageBase, *PtrAddOffset<uint32>(imageBase, *PtrAddOffset<uint32>(imageBase, 0x3C) + 40)))(peb); //Locate entry point offset in PE optional header, apply it to image base and run with PEB pointer as argument
	return 0;
}

//Injector
struct InjectionParameters
{
	ModuleHandle ImageBase;
	uint32 ImageSize;
	cwstr ExePath;
	uint32 ExePathSize;
	cwstr CommandLine;
	uint32 CommandLineSize;
	cwstr SteamApiPath;
	uint32 SteamApiPathSize;
	cwstr ModsDirectoryPathUnicode;
	uint32 ModsDirectoryPathUnicodeSize;
	cstr ModsDirectoryPathUtf8;
	uint32 ModsDirectoryPathUtf8Size;
	GameStatus Status;
	uint64 SteamId;
	bool ReduceIntegrityLevel;
	bool SetHighProcessPriority;
};
uint32 Inject(_In_ InjectionParameters& injParams) //Entry point called within host process, creates game process and injects shellcode image into it
{
	//Copy parameters that will be used inside game process into image space
	memcpy(SteamApiPath, injParams.SteamApiPath, SteamApiPathSize = injParams.SteamApiPathSize);
	memcpy(ModsDirectoryPathUnicode, injParams.ModsDirectoryPathUnicode, ModsDirectoryPathUnicodeSize = injParams.ModsDirectoryPathUnicodeSize);
	memcpy(ModsDirectoryPathUtf8, injParams.ModsDirectoryPathUtf8, ModsDirectoryPathUtf8Size = injParams.ModsDirectoryPathUtf8Size);
	Status = injParams.Status;
	SteamId = injParams.SteamId;
	//Create game process
	cwstr appId;
	uint64 appIdLength;
	if (Status == GameStatus::NotOwned)
	{
		appId = L"480";
		appIdLength = 3;
	}
	else
	{
		appId = L"346110";
		appIdLength = 6;
	}
	RtlSetEnvironmentVar(nullptr, L"SteamAppId", 10, appId, appIdLength);
	RtlSetEnvironmentVar(nullptr, L"GameAppId", 9, appId, appIdLength);
	ptr parameters;
	const UnicodeString imagePath{ static_cast<uint16>(injParams.ExePathSize), static_cast<uint16>(injParams.ExePathSize), injParams.ExePath };
	const wchar* cur = imagePath.Buffer + imagePath.Length;
	while (*--cur != L'\\');
	const uint16 currentDirectorySize = static_cast<uint16>((reinterpret_cast<const byte*>(++cur) - reinterpret_cast<const byte*>(imagePath.Buffer)) - 8);
	const uint16 commandLineSize = static_cast<uint16>(injParams.CommandLineSize);
	RtlCreateProcessParametersEx(parameters, imagePath, nullptr, { currentDirectorySize, currentDirectorySize, imagePath.Buffer + 4 }, { commandLineSize, commandLineSize, injParams.CommandLine }, nullptr, nullptr, nullptr, nullptr, nullptr, CreateProcessParametersFlags::Normalize);
	const ProcessCreateInformation createInformation{ sizeof(ProcessCreateInformation), { 0 } };
	ProcessAttributeList attributeList{ sizeof(ProcessAttributeList) - sizeof(ProcessAttribute), { { 0x20005, imagePath.Length, imagePath.Buffer, nullptr }, { 0x60002, 8, nullptr, nullptr } } };
	Handle mediumIntegrityToken;
	if (injParams.ReduceIntegrityLevel)
	{
		Handle token;
		NtOpenProcessToken(CurrentProcess, 0x2, token);
		const NtStatus status = NtDuplicateToken(token, 0x81, nullptr, false, TokenType::Primary, mediumIntegrityToken);
		NtClose(token);
		if (status)
		{
			RtlDestroyProcessParameters(parameters);
			return 1;
		}
		const uint32 sid[3]{ 0x101, 0x10000000, 0x2000 }; //Medium integrity level SID
		const TokenMandatoryLabel mandatoryLabel{ sid, 0x20 };
		if (NtSetInformationToken(mediumIntegrityToken, TokenInformationClass::IntegrityLevel, mandatoryLabel, sizeof(TokenMandatoryLabel)))
		{
			NtClose(mediumIntegrityToken);
			RtlDestroyProcessParameters(parameters);
			return 2;
		}
		attributeList.TotalSize = sizeof(ProcessAttributeList);
		attributeList.Attributes[1].Value = mediumIntegrityToken;
	}
	Handle process, thread;
	const NtStatus status = NtCreateUserProcess(process, thread, 0x1FFFFF, 0x1FFFFF, nullptr, nullptr, ProcessFlag::None, ThreadFlag::CreateSuspended, parameters, createInformation, attributeList);
	if (injParams.ReduceIntegrityLevel)
		NtClose(mediumIntegrityToken);
	RtlDestroyProcessParameters(parameters);
	if (status)
		return 3;
	//Set high priority if requested
	if (injParams.SetHighProcessPriority)
		NtSetInformationProcess(process, ProcessInformationClass::BasePriority, 0x300, 2);
	//Inject shellcode image
	uint32 exitCode;
	ptr region = nullptr;
	uint64 regionSize = injParams.ImageSize;
	if (NtAllocateVirtualMemory(process, region, 0, regionSize, PageAllocationType::ReserveAndCommit, PageProtection::ExecuteReadWrite))
	{
		exitCode = 4;
		goto Exit;
	}
	if (NtWriteVirtualMemory(process, region, injParams.ImageBase, injParams.ImageSize, nullptr))
	{
		exitCode = 5;
		goto Exit;
	}
	Handle shellcodeThread;
	//Create new main thread running ShellcodeMain()
	if (NtCreateThreadEx(shellcodeThread, 0x1FFFFF, nullptr, process, reinterpret_cast<const byte*>(ShellcodeMain) - reinterpret_cast<const byte*>(injParams.ImageBase) + reinterpret_cast<const byte*>(region), nullptr, 0, 0, 0, 0, nullptr))
	{
		exitCode = 6;
		goto Exit;
	}
	NtClose(shellcodeThread);
	//Terminate OS-created main thread, shellcode's thread will take that role
	NtTerminateThread(thread, 0);
	NtClose(thread);
	exitCode = 0;
Exit:
	NtClose(process);
	return exitCode;
}