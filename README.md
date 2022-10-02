# ARK Shellcode
[![Discord](https://img.shields.io/discord/937821572285206659?style=flat-square&label=Discord&logo=discord&logoColor=white&color=7289DA)](https://discord.gg/JBUgcwvpfc)

## Overview

ARK Shellcode is a collection of functions that upon injection into ARK: Survival Evolved process does the following:
- Disables game and DLC ownership checks by making them always succeed
- Adds a filter to prevent searching and displaying BattlEye-protected servers (so far there is no reliable method of getting shellcode to work in BattlEye-protected process in right moment)
- If game is not owned on current Steam account or app ID is set to 480, makes server list requests always use app ID 346110 and adds extra filter to prevent searching and displaying servers that don't use [TEK Wrapper](https://github.com/Nuclearistt/TEKWrapper)
- If current game installation doesn't belong to Steam or app ID is set to 480, overrides mod loading behaviour to load mods from **{Game root}\Mods** folder and list all mods there as subscribed, and also forwards all subscribe and download progress requests to [TEK Launcher](https://github.com/Nuclearistt/TEKLauncher) via its IPC infrastructure

The injector is also part of the project, both injector and shellcode are part of the same PE image that essentially copies itself into game process.

## How to use

ARK Shellcode is not supposed to be used directly. First, its PE image must be loaded into host process (TEK Launcher) address space, then host process must call image's Inject() function (pointed to by AddressOfEntryPoint field in PE optional header) with a reference to filled InjectionParameters structure.

## How does it work?

Inject() creates suspended game process with all needed parameters and copies shellcode image into its address space, then terminates OS-created main thread before it gets to execute any instructions and instead creates a thread running ShellcodeMain() that loads and initializes Steam API, then replaces DLL's internal pointers to Steam interfaces with wrappers that override certain method calls with calls to shellcode's functions and redirect the others to Steam interfaces. Afterwards, ShellcodeMain proceeds to execute game's entry point function as if nothing happened before, by the point game code runs SteamAPI_Init() it will return true as Steam API has already been initialized before, and thus no changes will be undone

## License

ARK Shellcode is licensed under the [MIT](LICENSE.TXT) license.
