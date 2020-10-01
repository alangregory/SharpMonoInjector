﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KernelMemorySharp;

namespace SharpMonoInjector
{
    public static class ProcessUtils
    {
        [DllImport("kernel32")] static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static void ShowConsole(IntPtr procHandle)
        {
            IntPtr allocConsoleAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "AllocConsole");
            var t = CreateRemoteThread(procHandle, IntPtr.Zero, 0, allocConsoleAddr, IntPtr.Zero, 0, IntPtr.Zero);
            Native.WaitForSingleObject(t, -1);
        }

        public static IEnumerable<ExportedFunction> GetExportedFunctions(IntPtr handle, IntPtr mod)
        {
            using (Memory memory = new Memory(handle)) {
                int e_lfanew = memory.ReadInt(mod + 0x3C);
                IntPtr ntHeaders = mod + e_lfanew;
                IntPtr optionalHeader = ntHeaders + 0x18;
                IntPtr dataDirectory = optionalHeader + (Is64BitProcess(handle) ? 0x70 : 0x60);
                IntPtr exportDirectory = mod + memory.ReadInt(dataDirectory);
                IntPtr names = mod + memory.ReadInt(exportDirectory + 0x20);
                IntPtr ordinals = mod + memory.ReadInt(exportDirectory + 0x24);
                IntPtr functions = mod + memory.ReadInt(exportDirectory + 0x1C);
                int count = memory.ReadInt(exportDirectory + 0x18);

                for (int i = 0; i < count; i++) {
                    int offset = memory.ReadInt(names + i * 4);
                    string name = memory.ReadString(mod + offset, 32, Encoding.ASCII);
                    short ordinal = memory.ReadShort(ordinals + i * 2);
                    IntPtr address = mod + memory.ReadInt(functions + ordinal * 4);

                    if (address != IntPtr.Zero)
                        yield return new ExportedFunction(name, address);
                }
            }
        }

        public static void InjectDll(String dll)
        {
            MemoryDriver.InjectDll(MemoryDriver._ProcessId, dll);
        }

        public static bool GetMonoModule(IntPtr handle, out IntPtr monoModule)
        {
            if (Memory.IsDriver)
            {
                monoModule = (IntPtr)MemoryDriver.GetModule("mono-2.0-bdwgc.dll");
                return monoModule != IntPtr.Zero;
            }
            int size = Is64BitProcess(handle) ? 8 : 4;

            IntPtr[] ptrs = new IntPtr[0];

            if (!Native.EnumProcessModulesEx(
                handle, ptrs, 0, out int bytesNeeded, ModuleFilter.LIST_MODULES_ALL)) {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            int count = bytesNeeded / size;
            ptrs = new IntPtr[count];

            if (!Native.EnumProcessModulesEx(
                handle, ptrs, bytesNeeded, out bytesNeeded, ModuleFilter.LIST_MODULES_ALL)) {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            for (int i = 0; i < count; i++) {
                StringBuilder path = new StringBuilder(260);
                Native.GetModuleFileNameEx(handle, ptrs[i], path, 260);

                if (path.ToString().IndexOf("mono", StringComparison.OrdinalIgnoreCase) > -1) {
                    if (!Native.GetModuleInformation(handle, ptrs[i], out MODULEINFO info, (uint)(size * ptrs.Length)))
                        throw new InjectorException("Failed to get module information", new Win32Exception(Marshal.GetLastWin32Error()));

                    var funcs = GetExportedFunctions(handle, info.lpBaseOfDll);

                    if (funcs.Any(f => f.Name == "mono_get_root_domain")) {
                        monoModule = info.lpBaseOfDll;
                        return true;
                    }
                }
            }

            monoModule = IntPtr.Zero;
            return false;
        }

        public static bool GetGameAssembly(IntPtr handle, out IntPtr unityModule)
        {
            if (Memory.IsDriver)
            {
                unityModule = (IntPtr)MemoryDriver.GetModule("UserAssembly.dll");
                if (unityModule == IntPtr.Zero)
                    unityModule = (IntPtr)MemoryDriver.GetModule("GameAssembly.dll");
                return unityModule != IntPtr.Zero;
            }
            int size = Is64BitProcess(handle) ? 8 : 4;

            IntPtr[] ptrs = new IntPtr[0];

            if (!Native.EnumProcessModulesEx(
                handle, ptrs, 0, out int bytesNeeded, ModuleFilter.LIST_MODULES_ALL)) {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            int count = bytesNeeded / size;
            ptrs = new IntPtr[count];

            if (!Native.EnumProcessModulesEx(
                handle, ptrs, bytesNeeded, out bytesNeeded, ModuleFilter.LIST_MODULES_ALL)) {
                throw new InjectorException("Failed to enumerate process modules", new Win32Exception(Marshal.GetLastWin32Error()));
            }

            for (int i = 0; i < count; i++) {
                StringBuilder path = new StringBuilder(260);
                Native.GetModuleFileNameEx(handle, ptrs[i], path, 260);

                if (path.ToString().IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) > -1) {
                    if (!Native.GetModuleInformation(handle, ptrs[i], out MODULEINFO info, (uint)(size * ptrs.Length)))
                        throw new InjectorException("Failed to get module information", new Win32Exception(Marshal.GetLastWin32Error()));

                    var funcs = GetExportedFunctions(handle, info.lpBaseOfDll);

                    if (funcs.Any(f => f.Name == "il2cpp_thread_attach")) {
                        monoModule = info.lpBaseOfDll;
                        return true;
                    }
                }
            }

            monoModule = IntPtr.Zero;
            return false;
        }

        public static bool Is64BitProcess(IntPtr handle)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!Native.IsWow64Process(handle, out bool isWow64))
                return IntPtr.Size == 8; // assume it's the same as the current process

            return !isWow64;
        }
    }
}
