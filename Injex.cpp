#include <fstream>
#include <stdio.h>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

// Static declarations
const char* PARAM_PID     = "-pid\0";
const char* PARAM_PNAME   = "-pname\0";
const char* PARAM_LAUNCH  = "-launch\0";
const char* PARAM_LIBPATH = "-path\0";
const char* PARAM_LIB     = "-lib\0";
const char* PARAM_REFRESH = "-refresh\0";
const char* PARAM_DELAY   = "-delay\0";

// Injection parameters
struct InjectionParams
{
  std::string ProcName;
  unsigned long ProcId;
  std::string LaunchPath;
  std::string LibraryPath;
  unsigned int RefreshRate;
  unsigned int InjectionDelay;
};

/****************************************************************************************
/ Function: OutputHelp
/ Notes: None.
****************************************************************************************/
void OutputHelp()
{
  printf("Params: <process> <library> <OPT:Refresh Rate> <OPT: Delay Before Injection>\n"
         " <process> -> [-pid processid] or [-pname processname] or [-launch \"path\"]\n"
         " <library> -> [-path \"path_to_dll\"] or [-lib dll_in_curr_path]\n"
         " <OPT:Refresh Rate> -> [-rate #ms]\n"
         " <OPT:Delay...> -> [-delay #ms]\n");
}

/****************************************************************************************
/ Function: RetrieveParameters
/ Notes: None.
****************************************************************************************/
bool RetrieveParameters(int count, char** arguments, InjectionParams& params)
{
  if (1 >= count)
  {
    printf("[error] Invalid parameter count %d\n", count);
    return false;
  }

  // Reset parameters
  params.ProcId = 0;
  params.ProcName = "";
  params.LaunchPath = "";
  params.LibraryPath = "";
  params.RefreshRate = 100;
  params.InjectionDelay = 0;

  // Retrieve all passed in arguments
  for (int param = 1; param < count; ++param)
  {
    const char* arg = reinterpret_cast<const char*>(arguments[param]);
    if (0 == _strcmpi(arg, PARAM_PID))
    {
      ++param;
      if (('0' == arg[param]) & (('x' == arg[param]) || ('X' == arg[param]))) // HEX
      {
        params.ProcId = strtoul(arguments[param], 0, 16);
      }
      else
      {
        params.ProcId = strtoul(arguments[param], 0, 10);
      }
    }
    else if (0 == _strcmpi(arg, PARAM_PNAME))
    {
      ++param;
      params.ProcName = arguments[param];
    }
    else if (0 == _strcmpi(arg, PARAM_LAUNCH))
    {
      ++param;
      params.LaunchPath = arguments[param];
    }
    else if (0 == _strcmpi(arg, PARAM_LIBPATH))
    {
      ++param;
      params.LibraryPath = arguments[param];
    }
    else if (0 == _strcmpi(arg, PARAM_LIB))
    {
      ++param;
      
      // Retrieve current directory and append the library name.
      char curr_dir[MAX_PATH] = {0};
      GetCurrentDirectoryA(MAX_PATH, curr_dir);
      params.LibraryPath = curr_dir;
      params.LibraryPath += "\\";
      params.LibraryPath += arguments[param];
    }
    else if (0 == _strcmpi(arg, PARAM_REFRESH))
    {
      ++param;
      params.RefreshRate = strtoul(arguments[param], 0, 10);
    }
    else if (0 == _strcmpi(arg, PARAM_DELAY))
    {
      ++param;
      params.InjectionDelay = strtoul(arguments[param], 0, 10);
    }
  }

  // Validate library path ...
  std::ifstream lib_file(params.LibraryPath.c_str(), std::ios::in);
  if (false == lib_file.is_open())
  {
    printf("[error] Library %s not found.. aborting.\n", params.LibraryPath.c_str());
    return false;
  }

  lib_file.close();

  if ((0 == params.ProcId) && 
      (0 == params.ProcName.length()) && 
      (0 == params.LaunchPath.length()))
  {
    printf("[error] Target process not specified.\n");
    return false;
  }

  return true;
}

/****************************************************************************************
/ Function: SetPrivilege
/ Notes: None.
****************************************************************************************/
bool SetPrivilege(LPCTSTR privName, bool enable)
{
  TOKEN_PRIVILEGES tokenPrivs;
  
  TOKEN_PRIVILEGES prevTokenPrivs;
  unsigned long tokenSize = sizeof(TOKEN_PRIVILEGES);

  HANDLE tokenHandle = INVALID_HANDLE_VALUE;
  if (0 == OpenThreadToken(GetCurrentThread(), 
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, 
                           &tokenHandle))
  {
    if (ERROR_NO_TOKEN == GetLastError())
    {
      if (0 == ImpersonateSelf(SecurityImpersonation))
      {
        return false;
      }
        
      if (0 == OpenThreadToken(GetCurrentThread(),
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE,
                               &tokenHandle))
      {
        return false;
      }
    }
  }

  LUID luid;
  if (0 == LookupPrivilegeValue(0, privName, &luid))
  {
    return false;
  }

  bool success = false;
  tokenPrivs.PrivilegeCount = 1;
  tokenPrivs.Privileges[0].Luid = luid;
  tokenPrivs.Privileges[0].Attributes = 0;
  AdjustTokenPrivileges(tokenHandle, FALSE, 
                        &tokenPrivs, sizeof(TOKEN_PRIVILEGES), 
                        &prevTokenPrivs, &tokenSize);
  if (ERROR_SUCCESS == GetLastError())
  {
    prevTokenPrivs.PrivilegeCount = 1;
    prevTokenPrivs.Privileges[0].Luid = luid;
    if (true == enable)
    {
      prevTokenPrivs.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
    }
    else
    {
      prevTokenPrivs.Privileges[0].Attributes ^= SE_PRIVILEGE_ENABLED;
    }

    AdjustTokenPrivileges(tokenHandle, FALSE, &prevTokenPrivs, tokenSize, 0, 0);
    if (ERROR_SUCCESS == GetLastError())
    {
      success = true;
    }
  }

  CloseHandle(tokenHandle);
  return success;
}

/****************************************************************************************
/ Function: GetProcessHandle
/ Notes: None.
****************************************************************************************/
HANDLE GetProcessHandle(InjectionParams* params)
{
  unsigned long targetProcessId = params->ProcId;
  HANDLE handle = INVALID_HANDLE_VALUE;

  // Output status
  printf("[notice] Waiting for target process...\n");

  // If a NULL pid was passed in, retrieve it via process name
  if (0 == targetProcessId)
  {
    while (0 == targetProcessId)
    {
      HANDLE hSnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if (INVALID_HANDLE_VALUE == hSnapHandle)
      {
        printf("[error] Failed creating process snapshot\n");
        return handle;
      }

      PROCESSENTRY32 pe32;
      pe32.dwSize = sizeof(PROCESSENTRY32);
      
      if (0 != Process32First(hSnapHandle, &pe32))
      {
        do
        {
          if (0 != pe32.th32ProcessID)
          {
            if (0 == memcmp(pe32.szExeFile, 
                            &params->ProcName[0], 
                            params->ProcName.length()))
            {
              targetProcessId = pe32.th32ProcessID;
              break;
            }
          }
        }
        while (0 != Process32Next(hSnapHandle, &pe32));
      }

      CloseHandle(hSnapHandle);
    
      if (0 == targetProcessId)
      {
        Sleep(params->RefreshRate);
      }
    }

    printf("[notice] %s found with id: %d\n", params->ProcName.c_str(), targetProcessId);
  }

  // We have a process id at this point, open the process for injection..
  if (0 != targetProcessId)
  {
    while (INVALID_HANDLE_VALUE == handle)
    {
      handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
      if (INVALID_HANDLE_VALUE != handle)
      {
        break;
      }

      Sleep(params->RefreshRate);
    }
  }

  return handle;
}

/****************************************************************************************
/ Function: InjectLibrary
/ Notes: None.
****************************************************************************************/
bool InjectLibrary(InjectionParams* params, HANDLE handle)
{
  bool success = false;
  if (INVALID_HANDLE_VALUE != handle)
  {
    // Allocate a buffer for our path
    void* path_buf = VirtualAllocEx(handle, 0, params->LibraryPath.length(),
                                    MEM_COMMIT, PAGE_READWRITE);
    if (0 != path_buf)
    {
      SIZE_T written = 0;
      WriteProcessMemory(handle, 
                         path_buf, 
                         params->LibraryPath.c_str(), 
                         params->LibraryPath.length(), 
                         &written);
      if (written == params->LibraryPath.length())
      {
        HMODULE hModule = GetModuleHandleA("Kernel32.dll");
        if (0 != hModule)
        {
          void* apiAddr = GetProcAddress(hModule, "LoadLibraryA");
          HANDLE hRemoteThread =
            CreateRemoteThread(handle, 0, 0,
              reinterpret_cast<LPTHREAD_START_ROUTINE>(apiAddr),
              path_buf, 0, 0);
          if (INVALID_HANDLE_VALUE != hRemoteThread)
          {
            success = true;
          }
        }
      }

      VirtualFreeEx(handle, path_buf, params->LibraryPath.length(), MEM_FREE);
    }
  }

  return success;
}


/****************************************************************************************
/ Function: ExecProcInjectLibrary
/ Notes: None.
****************************************************************************************/
bool ExecProcInjectLibrary(InjectionParams* params)
{
  STARTUPINFOA startupInfo;
  PROCESS_INFORMATION procInfo;

  // status
  printf("[notice] Launching process...\n");

  // Launch the process in suspended state
  std::string arguments = "";
  memset(&startupInfo, 0, sizeof(startupInfo));
  memset(&procInfo, 0, sizeof(procInfo));
  if (FALSE == CreateProcessA(params->LaunchPath.c_str(), &arguments[0], 0, 0, FALSE,
                              CREATE_SUSPENDED, 0, 0, &startupInfo, &procInfo))
  {
    printf("[error] Failed launching process, %08X\n", GetLastError());
    return false;
  }

  // Inject the library
  printf("[notice] Injecting library...\n");
  bool success = InjectLibrary(params, procInfo.hProcess);

  // Resume the process
  ResumeThread(procInfo.hThread);

  return success;
}

/****************************************************************************************
/ Function: EntryPoint
/ Notes: None.
****************************************************************************************/
int main(int argc, char* argv[])
{
  InjectionParams params;
  if (false == RetrieveParameters(argc, argv, params))
  {
    system("pause");
    return 0;
  }

  // If a null launch path was specified, we need to wait for the process..
  if (0 == params.LaunchPath.length())
  {
    // Elevate privileges..
    if (false == SetPrivilege(SE_DEBUG_NAME, true))
    {
      printf("[error] Failed escalating privileges\n");
      system("pause");
      return 0;
    }

    HANDLE processHandle = GetProcessHandle(&params);

    // Remove privileges...
    SetPrivilege(SE_DEBUG_NAME, false);

    // Inject the library
    if (false == InjectLibrary(&params, processHandle))
    {
      printf("[error] Library injection failed...\n");
    }
    else
    {
      printf("[notice] Library injected!\n");
    }

    CloseHandle(processHandle);
  }
  else // Launch path specified, create the process and inject the library.
  {
    if (false == ExecProcInjectLibrary(&params))
    {
      printf("[error] Library injection failed...\n");
    }
    else
    {
      printf("[notice] Library injected!\n");
    }
  }

  Sleep(3000);
  return 0;
}
