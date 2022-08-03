# ARK Shellcode
[![Discord](https://img.shields.io/discord/937821572285206659?style=flat-square&label=Discord&logo=discord&logoColor=white&color=7289DA)](https://discord.gg/JBUgcwvpfc)

## Overview

ARK Shellcode is a collection of functions that upon injection into ARK: Survival Evolved process does the following:
- Disables game and DLC ownership checks
- If game is not owned on current Steam account, makes server list requests always use app ID 346110 and adds extra filter for it to search only servers that use [TEK Wrapper](https://github.com/Nuclearistt/TEKWrapper)
- If current game installation doesn't belong to Steam, overrides mod loading behaviour to load mods from **{Game root}\Mods** folder and list all mods there as subscribed, and also forwards all subscribe and download progress requests to [TEK Launcher](https://github.com/Nuclearistt/TEKLauncher) via its IPC infrastructure

## How to use

ARK Shellcode is not supposed to be used directly, the exe file compiled by project is only used to extract functions' machine code from it, which is later arranged along with PayloadData structure into a 4 KB binary (Payload.bin in repository, its layout is described in Layout.txt) to be injected into game process. Payload is a self-sustainable executable image that doesn't follow PE format because it doesn't have to, but has its own area for imported functions and global variables. For payload to do the actual job a thread must be created in game process to run its Main() function.  

TEK Launcher has the payload built into its .exe file as a resource and implements the code for injecting it as described above

## How does it work?

ARK Shellcode makes use of the fact that Steam API provides its functionality as C++ interfaces, and the ability to change protection of any memory page in current process. It makes memory region that holds Steam API's virtual method tables writable and replaces certain method pointers with its own, essentially remapping Steam API functions and making them return desired result.

## License

ARK Shellcode is licensed under the [MIT](LICENSE.TXT) license.
