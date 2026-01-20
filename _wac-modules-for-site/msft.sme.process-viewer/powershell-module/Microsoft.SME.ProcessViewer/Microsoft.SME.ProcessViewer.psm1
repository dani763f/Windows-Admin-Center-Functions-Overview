function Get-WACPVCimNamespaceWithinMicrosoftWindows {
<#

.SYNOPSIS
Gets Namespace information under root/Microsoft/Windows

.DESCRIPTION
Gets Namespace information under root/Microsoft/Windows

.ROLE
Readers

#>

##SkipCheck=true##

Param(
)

import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows -Query "SELECT * FROM __NAMESPACE"

}
## [END] Get-WACPVCimNamespaceWithinMicrosoftWindows ##
function Get-WACPVCimProcess {
<#

.SYNOPSIS
Gets Msft_MTProcess objects.

.DESCRIPTION
Gets Msft_MTProcess objects.

.ROLE
Readers

#>

##SkipCheck=true##


import-module CimCmdlets

Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess

}
## [END] Get-WACPVCimProcess ##
function Get-WACPVProcessDownlevel {
<#

.SYNOPSIS
Gets information about the processes running in downlevel computer.

.DESCRIPTION
Gets information about the processes running in downlevel computer.

.ROLE
Readers

#>
param
(
    [Parameter(Mandatory = $true)]
    [boolean]
    $isLocal
)

$NativeProcessInfo = @"

namespace SMT
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;

    public class SystemProcess
    {
        public uint processId;
        public uint parentId;
        public string name;
        public string description;
        public string executablePath;
        public string userName;
        public string commandLine;
        public uint sessionId;
        public uint processStatus;
        public ulong cpuTime;
        public ulong cycleTime;
        public DateTime CreationDateTime;
        public ulong workingSetSize;
        public ulong peakWorkingSetSize;
        public ulong privateWorkingSetSize;
        public ulong sharedWorkingSetSize;
        public ulong commitCharge;
        public ulong pagedPool;
        public ulong nonPagedPool;
        public uint pageFaults;
        public uint basePriority;
        public uint handleCount;
        public uint threadCount;
        public uint userObjects;
        public uint gdiObjects;
        public ulong readOperationCount;
        public ulong writeOperationCount;
        public ulong otherOperationCount;
        public ulong readTransferCount;
        public ulong writeTransferCount;
        public ulong otherTransferCount;
        public bool elevated;
        public double cpuPercent;
        public uint operatingSystemContext;
        public uint platform;
        public double cyclePercent;
        public ushort uacVirtualization;
        public ushort dataExecutionPrevention;
        public bool isImmersive;
        public ushort intervalSeconds;
        public ushort deltaWorkingSetSize;
        public ushort deltaPageFaults;
        public bool hasChildWindow;
        public string processType;
        public string fileDescription;

        public SystemProcess(NativeMethods.SYSTEM_PROCESS_INFORMATION processInformation)
        {
            this.processId = (uint)processInformation.UniqueProcessId.ToInt32();
            this.name = Marshal.PtrToStringAuto(processInformation.ImageName.Buffer);
            this.cycleTime = processInformation.CycleTime;
            this.cpuTime = (ulong)(processInformation.KernelTime + processInformation.UserTime);
            this.sessionId = processInformation.SessionId;
            this.workingSetSize = (ulong)(processInformation.WorkingSetSize.ToInt64() / 1024);
            this.peakWorkingSetSize = (ulong)processInformation.PeakWorkingSetSize.ToInt64();
            this.privateWorkingSetSize = (ulong)processInformation.WorkingSetPrivateSize;
            this.sharedWorkingSetSize = (ulong)processInformation.WorkingSetSize.ToInt64() - this.privateWorkingSetSize;
            this.commitCharge = (ulong)processInformation.PrivatePageCount.ToInt64();
            this.pagedPool = (ulong)processInformation.QuotaPagedPoolUsage.ToInt64();
            this.nonPagedPool = (ulong)processInformation.QuotaNonPagedPoolUsage.ToInt64();
            this.pageFaults = processInformation.PageFaultCount;
            this.handleCount = processInformation.HandleCount;
            this.threadCount = processInformation.NumberOfThreads;
            this.readOperationCount = (ulong)processInformation.ReadOperationCount;
            this.writeOperationCount = (ulong)processInformation.WriteOperationCount;
            this.otherOperationCount = (ulong)processInformation.OtherOperationCount;
            this.readTransferCount = (ulong)processInformation.ReadTransferCount;
            this.writeTransferCount = (ulong)processInformation.WriteTransferCount;
            this.otherTransferCount = (ulong)processInformation.OtherTransferCount;
            this.processStatus = 0;

            if(processInformation.BasePriority <= 4)
            {
                this.basePriority = 0x00000040; //IDLE_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 6)
            {
                this.basePriority = 0x00004000; //BELOW_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 8)
            {
                this.basePriority = 0x00000020; //NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 10)
            {
                this.basePriority = 0x00008000; //ABOVE_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 13)
            {
                this.basePriority = 0x00000080; //HIGH_PRIORITY_CLASS
            }
            else
            {
                this.basePriority = 0x00000100; //REALTIME_PRIORITY_CLASS
            }
        }
    }

    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {
            internal uint NextEntryOffset;
            internal uint NumberOfThreads;
            internal long WorkingSetPrivateSize;
            internal uint HardFaultCount;
            internal uint NumberOfThreadsHighWatermark;
            internal ulong CycleTime;
            internal long CreateTime;
            internal long UserTime;
            internal long KernelTime;
            internal UNICODE_STRING ImageName;
            internal int BasePriority;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
            internal uint HandleCount;
            internal uint SessionId;
            internal IntPtr UniqueProcessKey;
            internal IntPtr PeakVirtualSize;
            internal IntPtr VirtualSize;
            internal uint PageFaultCount;
            internal IntPtr PeakWorkingSetSize;
            internal IntPtr WorkingSetSize;
            internal IntPtr QuotaPeakPagedPoolUsage;
            internal IntPtr QuotaPagedPoolUsage;
            internal IntPtr QuotaPeakNonPagedPoolUsage;
            internal IntPtr QuotaNonPagedPoolUsage;
            internal IntPtr PagefileUsage;
            internal IntPtr PeakPagefileUsage;
            internal IntPtr PrivatePageCount;
            internal long ReadOperationCount;
            internal long WriteOperationCount;
            internal long OtherOperationCount;
            internal long ReadTransferCount;
            internal long WriteTransferCount;
            internal long OtherTransferCount;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenElevation = 20,
            TokenVirtualizationAllowed = 23,
            TokenVirtualizationEnabled = 24
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public Int32 TokenIsElevated;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ALLOWED
        {
            public Int32 UacAllowed;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ENABLED
        {
            public Int32 UacEnabled;
        }

        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags DesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool InheritHandle, int ProcessId);

        [System.Runtime.InteropServices.DllImport("advapi32", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 desiredAccess, out Microsoft.Win32.SafeHandles.SafeWaitHandle hToken);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(SafeWaitHandle hToken, TOKEN_INFORMATION_CLASS tokenInfoClass, IntPtr pTokenInfo, Int32 tokenInfoLength, out Int32 returnLength);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        internal const int SystemProcessInformation = 5;

        internal const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        internal const uint TOKEN_QUERY = 0x0008;
    }

    public static class Process
    {
        public static IEnumerable<SystemProcess> Enumerate()
        {
            List<SystemProcess> process = new List<SystemProcess>();

            int bufferSize = 1024;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            QuerySystemProcessInformation(ref buffer, ref bufferSize);

            long totalOffset = 0;

            while (true)
            {
                IntPtr currentPtr = (IntPtr)((long)buffer + totalOffset);

                NativeMethods.SYSTEM_PROCESS_INFORMATION pi = new NativeMethods.SYSTEM_PROCESS_INFORMATION();

                pi = (NativeMethods.SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(currentPtr, typeof(NativeMethods.SYSTEM_PROCESS_INFORMATION));

                process.Add(new SystemProcess(pi));

                if (pi.NextEntryOffset == 0)
                {
                    break;
                }

                totalOffset += pi.NextEntryOffset;
            }

            Marshal.FreeHGlobal(buffer);

            GetExtendedProcessInfo(process);

            return process;
        }

        private static void GetExtendedProcessInfo(List<SystemProcess> processes)
        {
            foreach(var process in processes)
            {
                IntPtr hProcess = GetProcessHandle(process);

                if(hProcess != IntPtr.Zero)
                {
                    try
                    {
                        process.elevated = IsElevated(hProcess);
                        process.userObjects = GetCountUserResources(hProcess);
                        process.gdiObjects = GetCountGdiResources(hProcess);
                        process.uacVirtualization = GetVirtualizationStatus(hProcess);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProcess);
                    }
                }
            }
        }

        private static uint GetCountGdiResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 0);
        }
        private static uint GetCountUserResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 1);
        }

        private static ushort GetVirtualizationStatus(IntPtr hProcess)
        {
            /* Virtualization status:
             * 0: Unknown
             * 1: Disabled
             * 2: Enabled
             * 3: Not Allowed
             */
            ushort virtualizationStatus = 0;

            try
            {
                if(!IsVirtualizationAllowed(hProcess))
                {
                    virtualizationStatus = 3;
                }
                else
                {
                    if(IsVirtualizationEnabled(hProcess))
                    {
                        virtualizationStatus = 2;
                    }
                    else
                    {
                        virtualizationStatus = 1;
                    }
                }
            }
            catch(Win32Exception)
            {
            }

            return virtualizationStatus;
        }

        private static bool IsVirtualizationAllowed(IntPtr hProcess)
        {
            bool uacVirtualizationAllowed = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacAlowed = 0;
            IntPtr pUacAllowed = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacAlowed = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ALLOWED));
                pUacAllowed = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacAlowed);

                if (pUacAllowed == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationAllowed, pUacAllowed, cbUacAlowed, out cbUacAlowed))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ALLOWED uacAllowed = (NativeMethods.UAC_ALLOWED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacAllowed, typeof(NativeMethods.UAC_ALLOWED));

                uacVirtualizationAllowed = (uacAllowed.UacAllowed != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacAllowed != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacAllowed);
                    pUacAllowed = IntPtr.Zero;
                    cbUacAlowed = 0;
                }
            }

            return uacVirtualizationAllowed;
        }

        public static bool IsVirtualizationEnabled(IntPtr hProcess)
        {
            bool uacVirtualizationEnabled = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacEnabled = 0;
            IntPtr pUacEnabled = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacEnabled = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ENABLED));
                pUacEnabled = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacEnabled);

                if (pUacEnabled == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled, pUacEnabled, cbUacEnabled, out cbUacEnabled))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ENABLED uacEnabled = (NativeMethods.UAC_ENABLED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacEnabled, typeof(NativeMethods.UAC_ENABLED));

                uacVirtualizationEnabled = (uacEnabled.UacEnabled != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacEnabled != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacEnabled);
                    pUacEnabled = IntPtr.Zero;
                    cbUacEnabled = 0;
                }
            }

            return uacVirtualizationEnabled;
        }

        private static bool IsElevated(IntPtr hProcess)
        {
             bool fIsElevated = false;
            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbTokenElevation = 0;
            IntPtr pTokenElevation = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbTokenElevation = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.TOKEN_ELEVATION));
                pTokenElevation = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbTokenElevation);

                if (pTokenElevation == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, pTokenElevation, cbTokenElevation, out cbTokenElevation))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.TOKEN_ELEVATION elevation = (NativeMethods.TOKEN_ELEVATION)System.Runtime.InteropServices.Marshal.PtrToStructure(pTokenElevation, typeof(NativeMethods.TOKEN_ELEVATION));

                fIsElevated = (elevation.TokenIsElevated != 0);
            }
            catch (Win32Exception)
            {
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pTokenElevation != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pTokenElevation);
                    pTokenElevation = IntPtr.Zero;
                    cbTokenElevation = 0;
                }
            }

            return fIsElevated;
        }

        private static IntPtr GetProcessHandle(SystemProcess process)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);

            if(hProcess == IntPtr.Zero)
            {
                hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);
            }

            return hProcess;
        }

        private static void QuerySystemProcessInformation(ref IntPtr processInformationBuffer, ref int processInformationBufferSize)
        {
            const int maxTries = 10;
            bool success = false;

            for (int i = 0; i < maxTries; i++)
            {
                int sizeNeeded;

                int result = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemProcessInformation, processInformationBuffer, processInformationBufferSize, out sizeNeeded);

                if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    if (processInformationBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(processInformationBuffer);
                    }

                    processInformationBuffer = Marshal.AllocHGlobal(sizeNeeded);
                    processInformationBufferSize = sizeNeeded;
                }

                else if (result < 0)
                {
                    throw new Exception(String.Format("NtQuerySystemInformation failed with code 0x{0:X8}", result));
                }

                else
                {
                    success = true;
                    break;
                }
            }

            if (!success)
            {
                throw new Exception("Failed to allocate enough memory for NtQuerySystemInformation");
            }
        }
    }
}
"@

############################################################################################################################

# Global settings for the script.

############################################################################################################################

$ErrorActionPreference = "Stop"

Set-StrictMode -Version 3.0

############################################################################################################################

# Helper functions.

############################################################################################################################

function Get-ProcessListFromWmi {
    <#
    .Synopsis
        Name: Get-ProcessListFromWmi
        Description: Runs the WMI command to get Win32_Process objects and returns them in hashtable where key is processId.

    .Returns
        The list of processes in the form of hashtable.
    #>
    $processList = @{}

    $WmiProcessList = Get-WmiObject -Class Win32_Process

    foreach ($process in $WmiProcessList) {
        $processList.Add([int]$process.ProcessId, $process)
    }

    $processList
}

function Get-ProcessPerfListFromWmi {
    <#
    .Synopsis
        Name: Get-ProcessPerfListFromWmi
        Description: Runs the WMI command to get Win32_PerfFormattedData_PerfProc_Process objects and returns them in hashtable where key is processId.

    .Returns
        The list of processes performance data in the form of hashtable.
    #>
    $processPerfList = @{}

    $WmiProcessPerfList = Get-WmiObject -Class Win32_PerfFormattedData_PerfProc_Process

    foreach ($process in $WmiProcessPerfList) {
        try {
            $processPerfList.Add([int]$process.IdProcess, $process)
        }
        catch {
            if ($_.FullyQualifiedErrorId -eq 'ArgumentException') {
                $processPerfList.Remove([int]$process.IdProcess)
            }

            $processPerfList.Add([int]$process.IdProcess, $process)
        }
    }

    $processPerfList
}

function Get-ProcessListFromPowerShell {
    <#
    .Synopsis
        Name: Get-ProcessListFromPowerShell
        Description: Runs the PowerShell command Get-Process to get process objects.

    .Returns
        The list of processes in the form of hashtable.
    #>
    $processList = @{}

    if ($psVersionTable.psversion.Major -ge 4) {
        # It will crash to run 'Get-Process' with parameter 'IncludeUserName' multiple times in a session.
        # Currently the UI will not reuse the session as a workaround.
        # We need to remove the parameter 'IncludeUserName' if this issue happens again.
        try {
            $PowerShellProcessList = Get-Process -IncludeUserName
        } catch {
            # The 'IncludeUserName' parameter requires elevated user rights.
            if ($_.Exception.GetType().Name -eq 'InvalidOperationException') {
                $PowerShellProcessList = Get-Process -ErrorAction SilentlyContinue
            }
        }
    }
    else {
        $PowerShellProcessList = Get-Process -ErrorAction SilentlyContinue
    }

    foreach ($process in $PowerShellProcessList) {
        $processList.Add([int]$process.Id, $process)
    }

    $processList
}

function Get-LocalSystemAccount {
    <#
    .Synopsis
        Name: Get-LocalSystemAccount
        Description: Gets the name of local system account.

    .Returns
        The name local system account.
    #>
    $sidLocalSystemAccount = "S-1-5-18"

    $objSID = New-Object System.Security.Principal.SecurityIdentifier($sidLocalSystemAccount)

    $objSID.Translate( [System.Security.Principal.NTAccount]).Value
}

function Get-NumberOfLogicalProcessors {
    <#
    .Synopsis
        Name: Get-NumberOfLogicalProcessors
        Description: Gets the number of logical processors on the system.

    .Returns
        The number of logical processors on the system.
    #>
    $computerSystem = Get-CimInstance -Class Win32_ComputerSystem -Property NumberOfLogicalProcessors -ErrorAction Stop
    if ($computerSystem) {
        $computerSystem.NumberOfLogicalProcessors
    }
    else {
        throw 'Unable to get processor information'
    }
}


############################################################################################################################
# Main script.
############################################################################################################################

Add-Type -TypeDefinition $NativeProcessInfo
Remove-Variable NativeProcessInfo

try {
    #
    # Get the information about system processes from different sources.
    #
    $NumberOfLogicalProcessors = Get-NumberOfLogicalProcessors
    $NativeProcesses = [SMT.Process]::Enumerate()
    $WmiProcesses = Get-ProcessListFromWmi
    $WmiPerfProcesses = Get-ProcessPerfListFromWmi
    $PowerShellProcesses = Get-ProcessListFromPowerShell
    $LocalSystemAccount = Get-LocalSystemAccount

    $systemIdleProcess = $null
    $cpuInUse = 0

    # process paths and categorization taken from Task Manager
    # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
    $criticalProcesses = (
        "$($env:windir)\system32\winlogon.exe",
        "$($env:windir)\system32\wininit.exe",
        "$($env:windir)\system32\csrss.exe",
        "$($env:windir)\system32\lsass.exe",
        "$($env:windir)\system32\smss.exe",
        "$($env:windir)\system32\services.exe",
        "$($env:windir)\system32\taskeng.exe",
        "$($env:windir)\system32\taskhost.exe",
        "$($env:windir)\system32\dwm.exe",
        "$($env:windir)\system32\conhost.exe",
        "$($env:windir)\system32\svchost.exe",
        "$($env:windir)\system32\sihost.exe",
        "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
        "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
        "$($env:windir)\explorer.exe"
    )

    $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
    $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"

    $edgeProcesses = (
        "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
        "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
        "$($env:windir)\system32\browser_broker.exe"
    )

    #
    # Extract the additional process related information and fill up each nativeProcess object.
    #
    foreach ($nativeProcess in $NativeProcesses) {
        $WmiProcess = $null
        $WmiPerfProcess = $null
        $psProcess = $null

        # Same process as retrieved from WMI call Win32_Process
        if ($WmiProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
            $WmiProcess = $WmiProcesses.Get_Item([int]$nativeProcess.ProcessId)
        }

        # Same process as retrieved from WMI call Win32_PerfFormattedData_PerfProc_Process
        if ($WmiPerfProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
            $WmiPerfProcess = $WmiPerfProcesses.Get_Item([int]$nativeProcess.ProcessId)
        }

        # Same process as retrieved from PowerShell call Win32_Process
        if ($PowerShellProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
            $psProcess = $PowerShellProcesses.Get_Item([int]$nativeProcess.ProcessId)
        }

        if (($WmiProcess -eq $null) -or ($WmiPerfProcess -eq $null) -or ($psProcess -eq $null)) {continue}

        $nativeProcess.name = $WmiProcess.Name
        $nativeProcess.description = $WmiProcess.Description
        $nativeProcess.executablePath = $WmiProcess.ExecutablePath
        $nativeProcess.commandLine = $WmiProcess.CommandLine
        $nativeProcess.parentId = $WmiProcess.ParentProcessId

        #
        # Process CPU utilization and divide by number of cores
        # Win32_PerfFormattedData_PerfProc_Process PercentProcessorTime has a max number of 100 * cores so we want to normalize it
        #
        if ($WmiPerfProcess -and $WmiPerfProcess.PercentProcessorTime -ne $null -and $NumberOfLogicalProcessors -gt 0) {
            $nativeProcess.cpuPercent = $WmiPerfProcess.PercentProcessorTime / $NumberOfLogicalProcessors
        }
        #
        # Process start time.
        #
        if ($WmiProcess.CreationDate) {
            $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiProcess.CreationDate)
        }
        else {
            if ($nativeProcess.ProcessId -in @(0, 4)) {
                # Under some circumstances, the process creation time is not available for processs "System Idle Process" or "System"
                # In this case we assume that the process creation time is when the system was last booted.
                $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject -Class win32_Operatingsystem).LastBootUpTime)
            }
        }

        #
        # Owner of the process.
        #
        if ($psVersionTable.psversion.Major -ge 4) {
            try {
                $nativeProcess.userName = $psProcess.UserName
            } catch {
                ## ignore if UserName access has an error.
            }
        }

        # If UserName was not present available in results returned from Get-Process, then get the UserName from WMI class Get-Process
        <#
        ###### GetOwner is too slow so skip this part. ####

        if([string]::IsNullOrWhiteSpace($nativeProcess.userName))
        {
            $processOwner = Invoke-WmiMethod -InputObject $WmiProcess -Name GetOwner -ErrorAction SilentlyContinue

            try
            {
                if($processOwner.Domain)
                {
                    $nativeProcess.userName = "{0}\{1}" -f $processOwner.Domain, $processOwner.User
                }
                else
                {
                    $nativeProcess.userName = "{0}" -f $processOwner.User
                }
            }
            catch
            {
            }

            #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
            if([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4))
            {
                   $nativeProcess.userName = Get-LocalSystemAccount
            }
        }
        #>

        #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
        if ([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4)) {
            $nativeProcess.userName = $LocalSystemAccount
        } elseif ([string]::IsNullOrWhiteSpace($nativeProcess.userName)) {
            $nativeProcess.userName = '-'
        }

        #
        # The process status ( i.e. running or suspended )
        #
        $countSuspendedThreads = @($psProcess.Threads | where { $_.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended }).Count

        if ($psProcess.Threads.Count -eq $countSuspendedThreads) {
            $nativeProcess.ProcessStatus = 2
        }
        else {
            $nativeProcess.ProcessStatus = 1
        }

        # calculate system idle process
        if ($nativeProcess.processId -eq 0) {
            $systemIdleProcess = $nativeProcess
        }
        else {
            $cpuInUse += $nativeProcess.cpuPercent
        }


        if ($isLocal) {
            $nativeProcess.hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0

            if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                $nativeProcess.fileDescription = $psProcess.MainModule.FileVersionInfo.FileDescription
            }

            if ($edgeProcesses -contains $nativeProcess.executablePath) {
                # special handling for microsoft edge used by task manager
                # group all edge processes into applications
                $nativeProcess.fileDescription = 'Microsoft Edge'
                $nativeProcess.processType = 'application'
            }
            elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                    -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                # process is windows if its executable path is a critical process, defined by Task Manager
                # if the process has no executable path recorded, fallback to use the name to match to critical process
                $nativeProcess.processType = 'windows'
            }
            elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                $nativeProcess.processType = 'application'
            }
            else {
                $nativeProcess.processType = 'background'
            }
        }
    }

    if ($systemIdleProcess -ne $null) {
        $systemIdleProcess.cpuPercent = [Math]::Max(100 - $cpuInUse, 0)
    }

}
catch {
    throw $_
}
finally {
    $WmiProcesses = $null
    $WmiPerfProcesses = $null
}

# Return the result to the caller of this script.
$NativeProcesses


}
## [END] Get-WACPVProcessDownlevel ##
function Get-WACPVProcessHandle {
<#

.SYNOPSIS
Gets the filtered information of all the Operating System handles.

.DESCRIPTION
Gets the filtered information of all the Operating System handles.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory = $true, ParameterSetName = 'processId')]
    [int]
    $processId,

    [Parameter(Mandatory = $true, ParameterSetName = 'handleSubstring')]
    [string]
    $handleSubstring
)

$SystemHandlesInfo = @"
    
namespace SME
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    public static class NativeMethods
    {
        internal enum SYSTEM_INFORMATION_CLASS : int
        {
            /// </summary>
            SystemHandleInformation = 16
        }

        [Flags]
        internal enum ProcessAccessFlags : int
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SystemHandle
        {
            public Int32 ProcessId;
            public Byte ObjectTypeNumber;
            public Byte Flags;
            public UInt16 Handle;
            public IntPtr Object;
            public Int32 GrantedAccess;
        }

        [Flags]
        public enum DuplicateOptions : int
        {
            NONE = 0,
            /// <summary>
            /// Closes the source handle. This occurs regardless of any error status returned.
            /// </summary>
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            /// <summary>
            /// Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
            /// </summary>
            DUPLICATE_SAME_ACCESS = 0x00000002
        }

        internal enum OBJECT_INFORMATION_CLASS : int
        {
            /// <summary>
            /// Returns a PUBLIC_OBJECT_BASIC_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            /// <summary>
            /// Returns a PUBLIC_OBJECT_TYPE_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectTypeInformation = 2
        }

        public enum FileType : int
        {
            FileTypeChar = 0x0002,
            FileTypeDisk = 0x0001,
            FileTypePipe = 0x0003,
            FileTypeRemote = 0x8000,
            FileTypeUnknown = 0x0000,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            UInt32 GenericRead;
            UInt32 GenericWrite;
            UInt32 GenericExecute;
            UInt32 GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public UInt32 TotalNumberOfObjects;
            public UInt32 TotalNumberOfHandles;
            public UInt32 TotalPagedPoolUsage;
            public UInt32 TotalNonPagedPoolUsage;
            public UInt32 TotalNamePoolUsage;
            public UInt32 TotalHandleTableUsage;
            public UInt32 HighWaterNumberOfObjects;
            public UInt32 HighWaterNumberOfHandles;
            public UInt32 HighWaterPagedPoolUsage;
            public UInt32 HighWaterNonPagedPoolUsage;
            public UInt32 HighWaterNamePoolUsage;
            public UInt32 HighWaterHandleTableUsage;
            public UInt32 InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public UInt32 ValidAccessMask;
            public Boolean SecurityRequired;
            public Boolean MaintainHandleCount;
            public UInt32 PoolType;
            public UInt32 DefaultPagedPoolCharge;
            public UInt32 DefaultNonPagedPoolCharge;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String Buffer;
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            Int32 SystemInformationLength,
            out Int32 ReturnedLength);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            Int32 dwProcessId);

        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQueryObject(
            Int32 Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            Int32 ObjectInformationLength,
            out Int32 ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            UInt32 dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInheritHandle,
            DuplicateOptions dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryFullProcessImageName([In]IntPtr hProcess, [In]Int32 dwFlags, [Out]StringBuilder exeName, ref Int32 size);

        [DllImport("psapi.dll")]
        public static extern UInt32 GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder baseName, UInt32 size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueryDosDevice(String lpDeviceName, System.Text.StringBuilder lpTargetPath, Int32 ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern FileType GetFileType(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        internal const Int32 STATUS_INFO_LENGTH_MISMATCH = unchecked((Int32)0xC0000004L);
        internal const Int32 STATUS_SUCCESS = 0x00000000;
    }

    public class SystemHandles
    {
        private Queue<SystemHandle> systemHandles;
        private Int32 processId;
        String fileNameToMatch;
        Dictionary<Int32, IntPtr> processIdToHandle;
        Dictionary<Int32, String> processIdToImageName;
        private const Int32 GetObjectNameTimeoutMillis = 50;
        private Thread backgroundWorker;
        private static object syncRoot = new Object();

        public static IEnumerable<SystemHandle> EnumerateAllSystemHandles()
        {
            SystemHandles systemHandles = new SystemHandles();

            return systemHandles.Enumerate(HandlesEnumerationScope.AllSystemHandles);
        }
        public static IEnumerable<SystemHandle> EnumerateProcessSpecificHandles(Int32 processId)
        {
            SystemHandles systemHandles = new SystemHandles(processId);

            return systemHandles.Enumerate(HandlesEnumerationScope.ProcessSpecificHandles);
        }

        public static IEnumerable<SystemHandle> EnumerateMatchingFileNameHandles(String fileNameToMatch)
        {
            SystemHandles systemHandles = new SystemHandles(fileNameToMatch);

            return systemHandles.Enumerate(HandlesEnumerationScope.MatchingFileNameHandles);
        }

        private SystemHandles()
        { }

        public SystemHandles(Int32 processId)
        {
            this.processId = processId;
        }

        public SystemHandles(String fileNameToMatch)
        {
            this.fileNameToMatch = fileNameToMatch;
        }

        public IEnumerable<SystemHandle> Enumerate(HandlesEnumerationScope handlesEnumerationScope)
        {
            IEnumerable<SystemHandle> handles = null;

            this.backgroundWorker = new Thread(() => handles = Enumerate_Internal(handlesEnumerationScope));

            this.backgroundWorker.IsBackground = true;

            this.backgroundWorker.Start();

            return handles;
        }

        public bool IsBusy
        {
            get
            {
                return this.backgroundWorker.IsAlive;
            }
        }

        public bool WaitForEnumerationToComplete(int timeoutMillis)
        {
            return this.backgroundWorker.Join(timeoutMillis);
        }

        private IEnumerable<SystemHandle> Enumerate_Internal(HandlesEnumerationScope handlesEnumerationScope)
        {
            Int32 result;
            Int32 bufferLength = 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
            Int32 requiredLength;
            Int64 handleCount;
            Int32 offset = 0;
            IntPtr currentHandlePtr = IntPtr.Zero;
            NativeMethods.SystemHandle systemHandleStruct;
            Int32 systemHandleStructSize = 0;
            this.systemHandles = new Queue<SystemHandle>();
            this.processIdToHandle = new Dictionary<Int32, IntPtr>();
            this.processIdToImageName = new Dictionary<Int32, String>();

            while (true)
            {
                result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    buffer,
                    bufferLength,
                    out requiredLength);

                if (result == NativeMethods.STATUS_SUCCESS)
                {
                    break;
                }
                else if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferLength *= 2;
                    buffer = Marshal.AllocHGlobal(bufferLength);
                }
                else
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.InvariantCulture, "NtQuerySystemInformation failed with error code {0}", result));
                }
            } // End while loop.

            if (IntPtr.Size == 4)
            {
                handleCount = Marshal.ReadInt32(buffer);
            }
            else
            {
                handleCount = Marshal.ReadInt64(buffer);
            }

            offset = IntPtr.Size;
            systemHandleStruct = new NativeMethods.SystemHandle();
            systemHandleStructSize = Marshal.SizeOf(systemHandleStruct);

            if (handlesEnumerationScope == HandlesEnumerationScope.AllSystemHandles)
            {
                EnumerateAllSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.ProcessSpecificHandles)
            {
                EnumerateProcessSpecificSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.MatchingFileNameHandles)
            {
                this.EnumerateMatchingFileNameHandles(buffer, offset, systemHandleStructSize, handleCount);
            }

            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            this.Cleanup();

            return this.systemHandles;
        }

        public IEnumerable<SystemHandle> ExtractResults()
        {
            lock (syncRoot)
            {
                while (this.systemHandles.Count > 0)
                {
                    yield return this.systemHandles.Dequeue();
                }
            }
        }

        private void EnumerateAllSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandle(currentHandleInfo);

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateProcessSpecificSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                if (currentHandleInfo.ProcessId == this.processId)
                {
                    ExamineCurrentHandle(currentHandleInfo);
                }

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateMatchingFileNameHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandleForForMatchingFileName(currentHandleInfo, this.fileNameToMatch);

                offset += systemHandleStructSize;
            }
        }

        private void ExamineCurrentHandle(
            NativeMethods.SystemHandle currentHandleInfo)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            if (objectType != "File")
            {
                objectName = GetObjectName(duplicateHandle);
            }
            else
            {
                Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));
                getObjectNameThread.IsBackground = true;
                getObjectNameThread.Start();

                if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
                {
                    getObjectNameThread.Abort();

                    getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                    objectName = String.Empty;
                }
                else
                {
                    objectName = GetRegularFileName(objectName);
                }

                getObjectNameThread = null;
            }

            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                SystemHandle systemHandle = new SystemHandle();
                systemHandle.TypeName = objectType;
                systemHandle.Name = objectName;
                systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                systemHandle.ProcessId = currentHandleInfo.ProcessId;
                systemHandle.ProcessImageName = processImageName;

                RegisterHandle(systemHandle);
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void ExamineCurrentHandleForForMatchingFileName(
             NativeMethods.SystemHandle currentHandleInfo, String fileNameToMatch)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            if (String.IsNullOrWhiteSpace(processImageName))
            {
                return;
            }

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));

            getObjectNameThread.IsBackground = true;

            getObjectNameThread.Start();

            if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
            {
                getObjectNameThread.Abort();

                getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                objectName = String.Empty;
            }
            else
            {
                objectName = GetRegularFileName(objectName);
            }

            getObjectNameThread = null;


            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                if (objectName.ToLower().Contains(fileNameToMatch.ToLower()))
                {
                    SystemHandle systemHandle = new SystemHandle();
                    systemHandle.TypeName = objectType;
                    systemHandle.Name = objectName;
                    systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                    systemHandle.ProcessId = currentHandleInfo.ProcessId;
                    systemHandle.ProcessImageName = processImageName;

                    RegisterHandle(systemHandle);
                }
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void RegisterHandle(SystemHandle systemHandle)
        {
            lock (syncRoot)
            {
                this.systemHandles.Enqueue(systemHandle);
            }
        }

        private String GetObjectName(IntPtr duplicateHandle)
        {
            String objectName = String.Empty;
            IntPtr objectNameBuffer = IntPtr.Zero;

            try
            {
                Int32 objectNameBufferSize = 0x1000;
                objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);
                Int32 actualObjectNameLength;

                UInt32 queryObjectNameResult = NativeMethods.NtQueryObject(
                    duplicateHandle.ToInt32(),
                    NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    objectNameBuffer,
                    objectNameBufferSize,
                    out actualObjectNameLength);

                if (queryObjectNameResult != 0 && actualObjectNameLength > 0)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                    objectNameBufferSize = actualObjectNameLength;
                    objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);

                    queryObjectNameResult = NativeMethods.NtQueryObject(
                        duplicateHandle.ToInt32(),
                        NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                        objectNameBuffer,
                        objectNameBufferSize,
                        out actualObjectNameLength);
                }

                // Get the name
                if (queryObjectNameResult == 0)
                {
                    NativeMethods.UNICODE_STRING name = (NativeMethods.UNICODE_STRING)Marshal.PtrToStructure(objectNameBuffer, typeof(NativeMethods.UNICODE_STRING));

                    objectName = name.Buffer;
                }
            }
            catch (ThreadAbortException)
            {
            }
            finally
            {
                if (objectNameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                }
            }

            return objectName;
        }

        private String GetObjectType(IntPtr duplicateHandle)
        {
            String objectType = String.Empty;

            Int32 objectTypeBufferSize = 0x1000;
            IntPtr objectTypeBuffer = Marshal.AllocHGlobal(objectTypeBufferSize);
            Int32 actualObjectTypeLength;

            UInt32 queryObjectResult = NativeMethods.NtQueryObject(
                duplicateHandle.ToInt32(),
                NativeMethods.OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
                objectTypeBuffer,
                objectTypeBufferSize,
                out actualObjectTypeLength);

            if (queryObjectResult == 0)
            {
                NativeMethods.OBJECT_TYPE_INFORMATION typeInfo = (NativeMethods.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objectTypeBuffer, typeof(NativeMethods.OBJECT_TYPE_INFORMATION));

                objectType = typeInfo.TypeName.Buffer;
            }

            if (objectTypeBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(objectTypeBuffer);
            }

            return objectType;
        }

        private IntPtr GetProcessHandle(Int32 processId)
        {
            if (this.processIdToHandle.ContainsKey(processId))
            {
                return this.processIdToHandle[processId];
            }

            IntPtr processHandle = NativeMethods.OpenProcess
                (NativeMethods.ProcessAccessFlags.DupHandle | NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.VMRead, false, processId);

            if (processHandle != IntPtr.Zero)
            {
                this.processIdToHandle.Add(processId, processHandle);
            }
            else
            {
                // throw new Win32Exception(Marshal.GetLastWin32Error());
                //  Console.WriteLine("UNABLE TO OPEN PROCESS {0}", processId);
            }

            return processHandle;
        }

        private String GetProcessImageName(Int32 processId, IntPtr handleToProcess)
        {
            if (this.processIdToImageName.ContainsKey(processId))
            {
                return this.processIdToImageName[processId];
            }

            Int32 bufferSize = 1024;

            String strProcessImageName = String.Empty;

            StringBuilder processImageName = new StringBuilder(bufferSize);

            NativeMethods.QueryFullProcessImageName(handleToProcess, 0, processImageName, ref bufferSize);

            strProcessImageName = processImageName.ToString();

            if (!String.IsNullOrWhiteSpace(strProcessImageName))
            {
                try
                {
                    strProcessImageName = Path.GetFileName(strProcessImageName);
                }
                catch
                {
                }

                this.processIdToImageName.Add(processId, strProcessImageName);
            }

            return strProcessImageName;
        }

        private IntPtr CreateDuplicateHandle(IntPtr sourceProcessHandle, IntPtr handleToDuplicate)
        {
            IntPtr currentProcessHandle = Process.GetCurrentProcess().Handle;

            IntPtr duplicateHandle = IntPtr.Zero;

            NativeMethods.DuplicateHandle(
                sourceProcessHandle,
                handleToDuplicate,
                currentProcessHandle,
                out duplicateHandle,
                0,
                false,
                NativeMethods.DuplicateOptions.DUPLICATE_SAME_ACCESS);

            return duplicateHandle;
        }

        private static String GetRegularFileName(String deviceFileName)
        {
            String actualFileName = String.Empty;

            if (!String.IsNullOrWhiteSpace(deviceFileName))
            {
                foreach (var logicalDrive in Environment.GetLogicalDrives())
                {
                    StringBuilder targetPath = new StringBuilder(4096);

                    if (0 == NativeMethods.QueryDosDevice(logicalDrive.Substring(0, 2), targetPath, 4096))
                    {
                        return targetPath.ToString();
                    }

                    String targetPathStr = targetPath.ToString();

                    if (deviceFileName.StartsWith(targetPathStr))
                    {
                        actualFileName = deviceFileName.Replace(targetPathStr, logicalDrive.Substring(0, 2));

                        break;

                    }
                }

                if (String.IsNullOrWhiteSpace(actualFileName))
                {
                    actualFileName = deviceFileName;
                }
            }

            return actualFileName;
        }

        private void Cleanup()
        {
            foreach (var processHandle in this.processIdToHandle.Values)
            {
                NativeMethods.CloseHandle(processHandle);
            }

            this.processIdToHandle.Clear();
        }
    }

    public class SystemHandle
    {
        public String Name { get; set; }
        public String TypeName { get; set; }
        public byte ObjectTypeNumber { get; set; }
        public Int32 ProcessId { get; set; }
        public String ProcessImageName { get; set; }
    }
  
    public enum HandlesEnumerationScope
    {
        AllSystemHandles,
        ProcessSpecificHandles,
        MatchingFileNameHandles
    }
}
"@

############################################################################################################################

# Global settings for the script.

############################################################################################################################

$ErrorActionPreference = "Stop"

Set-StrictMode -Version 3.0

############################################################################################################################

# Main script.

############################################################################################################################


Add-Type -TypeDefinition $SystemHandlesInfo

Remove-Variable SystemHandlesInfo

if ($PSCmdlet.ParameterSetName -eq 'processId' -and $processId -ne $null) {

       $systemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $processId

       $scope = [SME.HandlesEnumerationScope]::ProcessSpecificHandles
}

elseif ($PSCmdlet.ParameterSetName -eq 'handleSubString') {
    
       $SystemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $handleSubstring

       $scope = [SME.HandlesEnumerationScope]::MatchingFileNameHandles
}


$SystemHandlesFinder.Enumerate($scope) | out-null

while($SystemHandlesFinder.IsBusy)
{
    $SystemHandlesFinder.ExtractResults() | Write-Output
    $SystemHandlesFinder.WaitForEnumerationToComplete(50) | out-null
}

$SystemHandlesFinder.ExtractResults() | Write-Output
}
## [END] Get-WACPVProcessHandle ##
function Get-WACPVProcessModule {
<#

.SYNOPSIS
Gets services associated with the process.

.DESCRIPTION
Gets services associated with the process.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory=$true)]
    [UInt32]
    $processId
)

$process = Get-Process -PID $processId
$process.Modules | Microsoft.PowerShell.Utility\Select-Object ModuleName, FileVersion, FileName, @{Name="Image"; Expression={$process.Name}}, @{Name="PID"; Expression={$process.id}}


}
## [END] Get-WACPVProcessModule ##
function Get-WACPVProcessService {
<#

.SYNOPSIS
Gets services associated with the process.

.DESCRIPTION
Gets services associated with the process.

.ROLE
Readers

#>

param (
    [Parameter(Mandatory=$true)]
    [Int32]
    $processId
)

Import-Module CimCmdlets -ErrorAction SilentlyContinue

Get-CimInstance -ClassName Win32_service | Where-Object {$_.ProcessId -eq $processId} | Microsoft.PowerShell.Utility\Select-Object Name, processId, Description, Status, StartName



}
## [END] Get-WACPVProcessService ##
function Get-WACPVProcesses {
<#

.SYNOPSIS
Gets information about the processes running in computer.

.DESCRIPTION
Gets information about the processes running in computer.

.ROLE
Readers

.COMPONENT
ProcessList_Body

#>
param
(
    [Parameter(Mandatory = $true)]
    [boolean]
    $isLocal
)

Import-Module CimCmdlets -ErrorAction SilentlyContinue

$processes = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess

$powershellProcessList = @{}
$powerShellProcesses = Get-Process -ErrorAction SilentlyContinue

foreach ($process in $powerShellProcesses) {
    $powershellProcessList.Add([int]$process.Id, $process)
}

if ($isLocal) {
    # critical processes taken from task manager code
    # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
    $criticalProcesses = (
        "$($env:windir)\system32\winlogon.exe",
        "$($env:windir)\system32\wininit.exe",
        "$($env:windir)\system32\csrss.exe",
        "$($env:windir)\system32\lsass.exe",
        "$($env:windir)\system32\smss.exe",
        "$($env:windir)\system32\services.exe",
        "$($env:windir)\system32\taskeng.exe",
        "$($env:windir)\system32\taskhost.exe",
        "$($env:windir)\system32\dwm.exe",
        "$($env:windir)\system32\conhost.exe",
        "$($env:windir)\system32\svchost.exe",
        "$($env:windir)\system32\sihost.exe",
        "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
        "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
        "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
        "$($env:windir)\explorer.exe"
    )

    $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
    $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"

    $edgeProcesses = (
        "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
        "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
        "$($env:windir)\system32\browser_broker.exe"
    )

    foreach ($process in $processes) {

        if ($powershellProcessList.ContainsKey([int]$process.ProcessId)) {
            $psProcess = $powershellProcessList.Get_Item([int]$process.ProcessId)
            $hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0
            $process | Add-Member -MemberType NoteProperty -Name "HasChildWindow" -Value $hasChildWindow
            if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $psProcess.MainModule.FileVersionInfo.FileDescription
            }
        }

        if ($edgeProcesses -contains $nativeProcess.executablePath) {
            # special handling for microsoft edge used by task manager
            # group all edge processes into applications
            $edgeLabel = 'Microsoft Edge'
            if ($process.fileDescription) {
                $process.fileDescription = $edgeLabel
            }
            else {
                $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $edgeLabel
            }

            $processType = 'application'
        }
        elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
            # process is windows if its executable path is a critical process, defined by Task Manager
            # if the process has no executable path recorded, fallback to use the name to match to critical process
            $processType = 'windows'
        }
        elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
            # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
            $processType = 'application'
        }
        else {
            $processType = 'background'
        }

        $process | Add-Member -MemberType NoteProperty -Name "ProcessType" -Value $processType
    }
}

$processes

}
## [END] Get-WACPVProcesses ##
function New-WACPVCimProcessDump {
<#

.SYNOPSIS
Creates a new process dump.

.DESCRIPTION
Creates a new process dump.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[System.UInt16]$ProcessId
)

import-module CimCmdlets

$keyInstance = New-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -Key @('ProcessId') -Property @{ProcessId=$ProcessId;} -ClientOnly
Invoke-CimMethod $keyInstance -MethodName CreateDump

}
## [END] New-WACPVCimProcessDump ##
function New-WACPVProcessDumpDownlevel {
<#

.SYNOPSIS
Creates the mini dump of the process on downlevel computer.

.DESCRIPTION
Creates the mini dump of the process on downlevel computer.

.ROLE
Administrators

#>

param
(
    # The process ID of the process whose mini dump is supposed to be created.
    [int]
    $processId,

    # Path to the process dump file name.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $fileName
)

$NativeCode = @"

    namespace SME
    {
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;

        public static class ProcessMiniDump
        {
            private enum MINIDUMP_TYPE
            {
                MiniDumpNormal = 0x00000000,
                MiniDumpWithDataSegs = 0x00000001,
                MiniDumpWithFullMemory = 0x00000002,
                MiniDumpWithHandleData = 0x00000004,
                MiniDumpFilterMemory = 0x00000008,
                MiniDumpScanMemory = 0x00000010,
                MiniDumpWithUnloadedModules = 0x00000020,
                MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
                MiniDumpFilterModulePaths = 0x00000080,
                MiniDumpWithProcessThreadData = 0x00000100,
                MiniDumpWithPrivateReadWriteMemory = 0x00000200,
                MiniDumpWithoutOptionalData = 0x00000400,
                MiniDumpWithFullMemoryInfo = 0x00000800,
                MiniDumpWithThreadInfo = 0x00001000,
                MiniDumpWithCodeSegs = 0x00002000
            };

            [DllImport("dbghelp.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            private extern static bool MiniDumpWriteDump(
                System.IntPtr hProcess,
                int processId,
                Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
                MINIDUMP_TYPE dumpType,
                System.IntPtr exceptionParam,
                System.IntPtr userStreamParam,
                System.IntPtr callbackParam);

            public static void Create(int processId, string fileName)
            {
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    throw new ArgumentNullException(fileName);
                }

                if (processId < 0)
                {
                    throw new ArgumentException("Incorrect value of ProcessId", "processId");
                }

                System.IO.FileStream fileStream = null;

                try
                {
                    fileStream = System.IO.File.OpenWrite(fileName);
                    var proc = Process.GetProcessById(processId);

                    bool success = MiniDumpWriteDump(
                        proc.Handle,
                        proc.Id,
                        fileStream.SafeFileHandle,
                        MINIDUMP_TYPE.MiniDumpWithFullMemory | MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo | MINIDUMP_TYPE.MiniDumpWithHandleData | MINIDUMP_TYPE.MiniDumpWithUnloadedModules | MINIDUMP_TYPE.MiniDumpWithThreadInfo,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    if (!success)
                    {
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }
                }
                finally
                {
                    if (fileStream != null)
                    {
                        fileStream.Close();
                    }
                }
            }
        }
}

"@

############################################################################################################################

# Global settings for the script.

############################################################################################################################

$ErrorActionPreference = "Stop"

Set-StrictMode -Version 3.0

############################################################################################################################

# Main script.

############################################################################################################################

Add-Type -TypeDefinition $NativeCode
Remove-Variable NativeCode

$fileName = "$($env:temp)\$($fileName)"

try {
    # Create the mini dump using native call.
    try {
        [SME.ProcessMiniDump]::Create($processId, $fileName)
        $result = New-Object PSObject
        $result | Add-Member -MemberType NoteProperty -Name 'DumpFilePath' -Value $fileName
        $result
    }
    catch {
        if ($_.FullyQualifiedErrorId -eq "ArgumentException") {
            throw "Unable to create the mini dump of the process. Please make sure that the processId is correct and the user has required permissions to create the mini dump of the process."
        }
        elseif ($_.FullyQualifiedErrorId -eq "UnauthorizedAccessException") {
            throw "Access is denied. User does not relevant permissions to create the mini dump of process with ID: {0}" -f $processId
        }
        else {
            throw
        }
    }
}
finally {
    if (Test-Path $fileName) {
        if ((Get-Item $fileName).length -eq 0) {
            # Delete the zero byte file.
            Remove-Item -Path $fileName -Force -ErrorAction Stop
        }
    }
}

}
## [END] New-WACPVProcessDumpDownlevel ##
function Start-WACPVCimProcess {
<#

.SYNOPSIS
Starts new process.

.DESCRIPTION
Starts new process.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[string]$CommandLine
)

import-module CimCmdlets

Invoke-CimMethod -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -MethodName CreateProcess -Arguments @{CommandLine=$CommandLine;}

}
## [END] Start-WACPVCimProcess ##
function Start-WACPVProcessDownlevel {
<#

.SYNOPSIS
Start a new process on downlevel computer.

.DESCRIPTION
Start a new process on downlevel computer.

.ROLE
Administrators

#>

param
(
	[Parameter(Mandatory = $true)]
	[string]
	$commandLine
)

Set-StrictMode -Version 5.0

Start-Process $commandLine

}
## [END] Start-WACPVProcessDownlevel ##
function Stop-WACPVCimProcess {
<#

.SYNOPSIS
Stop a process.

.DESCRIPTION
Stop a process.

.ROLE
Administrators

#>

##SkipCheck=true##

Param(
[System.UInt16]$ProcessId
)

import-module CimCmdlets

$instance = New-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -Key @('ProcessId') -Property @{ProcessId=$ProcessId;} -ClientOnly
Remove-CimInstance $instance

}
## [END] Stop-WACPVCimProcess ##
function Stop-WACPVProcesses {
<#

.SYNOPSIS
Stop the process on a computer.

.DESCRIPTION
Stop the process on a computer.

.ROLE
Administrators

#>

param
(
	[Parameter(Mandatory = $true)]
	[int[]]
	$processIds
)

Set-StrictMode -Version 5.0

Stop-Process $processIds -Force

}
## [END] Stop-WACPVProcesses ##

# SIG # Begin signature block
# MIIoLQYJKoZIhvcNAQcCoIIoHjCCKBoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIMElJHr1uLACc
# A2eO/pGLzecvHJGknmFAwaJOR/kgeKCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
# 7A5ZL83XAAAAAASFMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM3WhcNMjYwNjE3MTgyMTM3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDASkh1cpvuUqfbqxele7LCSHEamVNBfFE4uY1FkGsAdUF/vnjpE1dnAD9vMOqy
# 5ZO49ILhP4jiP/P2Pn9ao+5TDtKmcQ+pZdzbG7t43yRXJC3nXvTGQroodPi9USQi
# 9rI+0gwuXRKBII7L+k3kMkKLmFrsWUjzgXVCLYa6ZH7BCALAcJWZTwWPoiT4HpqQ
# hJcYLB7pfetAVCeBEVZD8itKQ6QA5/LQR+9X6dlSj4Vxta4JnpxvgSrkjXCz+tlJ
# 67ABZ551lw23RWU1uyfgCfEFhBfiyPR2WSjskPl9ap6qrf8fNQ1sGYun2p4JdXxe
# UAKf1hVa/3TQXjvPTiRXCnJPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUuCZyGiCuLYE0aU7j5TFqY05kko0w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwNTM1OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACjmqAp2Ci4sTHZci+qk
# tEAKsFk5HNVGKyWR2rFGXsd7cggZ04H5U4SV0fAL6fOE9dLvt4I7HBHLhpGdE5Uj
# Ly4NxLTG2bDAkeAVmxmd2uKWVGKym1aarDxXfv3GCN4mRX+Pn4c+py3S/6Kkt5eS
# DAIIsrzKw3Kh2SW1hCwXX/k1v4b+NH1Fjl+i/xPJspXCFuZB4aC5FLT5fgbRKqns
# WeAdn8DsrYQhT3QXLt6Nv3/dMzv7G/Cdpbdcoul8FYl+t3dmXM+SIClC3l2ae0wO
# lNrQ42yQEycuPU5OoqLT85jsZ7+4CaScfFINlO7l7Y7r/xauqHbSPQ1r3oIC+e71
# 5s2G3ClZa3y99aYx2lnXYe1srcrIx8NAXTViiypXVn9ZGmEkfNcfDiqGQwkml5z9
# nm3pWiBZ69adaBBbAFEjyJG4y0a76bel/4sDCVvaZzLM3TFbxVO9BQrjZRtbJZbk
# C3XArpLqZSfx53SuYdddxPX8pvcqFuEu8wcUeD05t9xNbJ4TtdAECJlEi0vvBxlm
# M5tzFXy2qZeqPMXHSQYqPgZ9jvScZ6NwznFD0+33kbzyhOSz/WuGbAu4cHZG8gKn
# lQVT4uA2Diex9DMs2WHiokNknYlLoUeWXW1QrJLpqO82TLyKTbBM/oZHAdIc0kzo
# STro9b3+vjn2809D0+SOOCVZMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGg0wghoJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIILN4hc8Sd4RKnC1OHRTgBjH
# NxE91f2CYZkHsiZdf7A2MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAL0KqJ56Ds4b+6UNbyCx93Cgq29vxJdH5y+/cqNmTDrHS+PWRyumtx7qh
# 26V6CvPP3siS53NlK8s4w/CSzEZKQL47hRQLm/Vfu18D4s+59cqql6113ht/BhHE
# bYTSEw5iCcwS7UFjXfCZQuEOIpZM89XaS0hs3tcmSjOUOevyQeujgq92AEHH62xJ
# hfb78R3fAbUnWSKn8bwUQubo4Q0Ou/81Tz9xA0vJPuPIWle6bOwZSzmqblPn2aSq
# SYv6Hrwwf+J+cx70htrL324uwXuUhD8M+B+eYcDUfC+adRL/GwlBAIWzb87W+Pzs
# ko0IdjsXIyfR+NjKCOE0ZsruiXOiVKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCC
# F38GCSqGSIb3DQEHAqCCF3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsq
# hkiG9w0BCRABBKCCAUEEggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDiCR2X8piuJwDVuXqCvN2mlmlY80Ofi2Ml6V5v11+91gIGaPCDIpg+
# GBMyMDI1MTExMDE3MTczMy4wNTFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0w
# NUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghHtMIIHIDCCBQigAwIBAgITMwAAAgpHshTZ7rKzDwABAAACCjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yNTAxMzAxOTQy
# NTdaFw0yNjA0MjIxOTQyNTdaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCy7NzwEpb7BpwAk9LJ00Xq30TcTjcwNZ80TxAtAbhS
# aJ2kwnJA1Au/Do9/fEBjAHv6Mmtt3fmPDeIJnQ7VBeIq8RcfjcjrbPIg3wA5v5MQ
# flPNSBNOvcXRP+fZnAy0ELDzfnJHnCkZNsQUZ7GF7LxULTKOYY2YJw4TrmcHohkY
# 6DjCZyxhqmGQwwdbjoPWRbYu/ozFem/yfJPyjVBql1068bcVh58A8c5CD6TWN/L3
# u+Ny+7O8+Dver6qBT44Ey7pfPZMZ1Hi7yvCLv5LGzSB6o2OD5GIZy7z4kh8UYHdz
# jn9Wx+QZ2233SJQKtZhpI7uHf3oMTg0zanQfz7mgudefmGBrQEg1ox3n+3Tizh0D
# 9zVmNQP9sFjsPQtNGZ9ID9H8A+kFInx4mrSxA2SyGMOQcxlGM30ktIKM3iqCuFEU
# 9CHVMpN94/1fl4T6PonJ+/oWJqFlatYuMKv2Z8uiprnFcAxCpOsDIVBO9K1vHeAM
# iQQUlcE9CD536I1YLnmO2qHagPPmXhdOGrHUnCUtop21elukHh75q/5zH+OnNekp
# 5udpjQNZCviYAZdHsLnkU0NfUAr6r1UqDcSq1yf5RiwimB8SjsdmHll4gPjmqVi0
# /rmnM1oAEQm3PyWcTQQibYLiuKN7Y4io5bJTVwm+vRRbpJ5UL/D33C//7qnHbeoW
# BQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFAKvF0EEj4AyPfY8W/qrsAvftZwkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQCwk3PW0CyjOaqXCMOusTde7ep2CwP/xV1J
# 3o9KAiKSdq8a2UR5RCHYhnJseemweMUH2kNefpnAh2Bn8H2opDztDJkj8OYRd/KQ
# ysE12NwaY3KOwAW8Rg8OdXv5fUZIsOWgprkCQM0VoFHdXYExkJN3EzBbUCUw3yb4
# gAFPK56T+6cPpI8MJLJCQXHNMgti2QZhX9KkfRAffFYMFcpsbI+oziC5Brrk3361
# cJFHhgEJR0J42nqZTGSgUpDGHSZARGqNcAV5h+OQDLeF2p3URx/P6McUg1nJ2gMP
# YBsD+bwd9B0c/XIZ9Mt3ujlELPpkijjCdSZxhzu2M3SZWJr57uY+FC+LspvIOH1O
# pofanh3JGDosNcAEu9yUMWKsEBMngD6VWQSQYZ6X9F80zCoeZwTq0i9AujnYzzx5
# W2fEgZejRu6K1GCASmztNlYJlACjqafWRofTqkJhV/J2v97X3ruDvfpuOuQoUtVA
# wXrDsG2NOBuvVso5KdW54hBSsz/4+ORB4qLnq4/GNtajUHorKRKHGOgFo8DKaXG+
# UNANwhGNxHbILSa59PxExMgCjBRP3828yGKsquSEzzLNWnz5af9ZmeH4809fwItt
# I41JkuiY9X6hmMmLYv8OY34vvOK+zyxkS+9BULVAP6gt+yaHaBlrln8Gi4/dBr2y
# 6Srr/56g0DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQ
# MIICOAIBATCB+aGB0aSBzjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEn
# MCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjM3MDMtMDVFMC1EOTQ3MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDR
# AMVJlA6bKq93Vnu3UkJgm5HlYaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMA0GCSqGSIb3DQEBCwUAAgUA7LycnTAiGA8yMDI1MTExMDE3MTcx
# N1oYDzIwMjUxMTExMTcxNzE3WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDsvJyd
# AgEAMAoCAQACAhf6AgH/MAcCAQACAhJrMAoCBQDsve4dAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQELBQADggEBAI3gTyGN+5LkgGY4QxM0L7tJDHfcVkG33F/yu3txriDl
# S8QNlSzYRkLH0ZuLibga8OT3JWHfkOo+A/vE4iILJmh5Z6bXFl7SElmzWt3oTPzI
# bW7Y7DZtWDGIImUEVkn4a5BKMJx0p/mzjYubkcfUQMxi0tU5woY/Wyk6vEGHnq6C
# Y0MZd0KfzS80hUReWT4GrYirJMuGay+ckayIWjL55rVI7imPkbYtT6sogJGJbEp8
# Jd74g9A+A6kXUUZd7zGuyL/sWOlhaE9YPzMNCnoDYCaYaxceNAwES/4vJkLEK91n
# egnbcBb3E/I2wKsUHKVlii9RbqnYMgLPQ5Our/tdbPgxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgpHshTZ7rKzDwABAAAC
# CjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCBS5JbOkcw9+/hpSo2jKt/MZuZGc+kgUHqEY5+6xtsD
# 4DCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIE2ay/y0epK/X3Z03KTcloqE
# 8u9IXRtdO7Mex0hw9+SaMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAIKR7IU2e6ysw8AAQAAAgowIgQgR/ENq/vuzHvyekbyqi3ksXrB
# zoR6QXMGpmTUUdGI5CcwDQYJKoZIhvcNAQELBQAEggIAIJsdNgbJIozFZ1shJx7x
# kQhSVEnxSBzyfdkaLkXafQFyScprJucTAmjZKP5pTFKrf5dSBATNdZSNLPo4hw1E
# /zwuV4jKsZjMHsJLyEm8h7Tx+OqGnDr7WZR9loK4rfppNS/HP3cPK4/w47PohhEa
# qHp0SZ8RnxOKtO2n/lmXSxoy93/IqyZJ8LHK47FaW8nXsChsK03IvCxEmZXQL3ah
# bd8Kpeutbxx9KimO1fAdFu4sddkZLI706sHNB5/bE9/qz3vlnUX7O6usJgy3Yx0Y
# cDQv+ZsjnQv1wranKfVwX1mQF3ymjpbVyiGNgvmQREZ1JjhOBkjW0BcA+BKIAMfh
# Nn1FQCa8aVnbovuMRyUbb1P+p6n1Bp+Oo1/N2me9JMOgNmcWoW+pkfSHyC1MNKtw
# OXRJayE4YnEEopGjFVsZ2rYCg2/dPdIuWMhPrrO2GlJCg6pXM8jdJl1To6aBTVYi
# P0sffumWs4ml3J6dvRFRtU105VAbTkxHR1QBiPyFAFqcIBI2KmpxdDW/Grc26tX1
# C0ORacPlqC4moSz3Wimbn7uk0DQ5SpvZwwTc+cLMZBFFJVPqOzLLPpXmNrZDXk66
# 9Tdm1dJbvRRAQqkEMbh/Eld1k/9eNDcqp0XakcU7Jri6bkTumPsUIHGfNhJjhsvP
# e3jV5Ey7/M5kSiOgxoEo4EA=
# SIG # End signature block
