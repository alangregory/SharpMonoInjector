using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpMonoInjector
{
    public class Injector : IDisposable
    {
        private const string mono_get_root_domain = "mono_get_root_domain";
        private const string mono_thread_attach = "mono_thread_attach";
        private const string mono_image_open_from_data = "mono_image_open_from_data";
        private const string mono_assembly_load_from_full = "mono_assembly_load_from_full";
        private const string mono_assembly_get_image = "mono_assembly_get_image";
        private const string mono_class_from_name = "mono_class_from_name";
        private const string mono_class_get_method_from_name = "mono_class_get_method_from_name";
        private const string mono_runtime_invoke = "mono_runtime_invoke";
        private const string mono_assembly_close = "mono_assembly_close";
        private const string mono_image_strerror = "mono_image_strerror";
        private const string mono_object_get_class = "mono_object_get_class";
        private const string mono_class_get_name = "mono_class_get_name";
        private const string mono_set_assemblies_path = "mono_set_assemblies_path";
        private const string mono_assembly_setrootdir = "mono_assembly_setrootdir";
        private const string mono_set_config_dir = "mono_set_config_dir";
        private const string mono_jit_init = "mono_jit_init";

        private const string il2cpp_thread_attach = "il2cpp_thread_attach";
        private const string il2cpp_domain_get = "il2cpp_domain_get";

        private readonly Dictionary<string, IntPtr> Exports = new Dictionary<string, IntPtr>
        {
            { mono_get_root_domain, IntPtr.Zero },
            { il2cpp_domain_get, IntPtr.Zero },
            { mono_thread_attach, IntPtr.Zero },
            { il2cpp_thread_attach, IntPtr.Zero },
            { mono_image_open_from_data, IntPtr.Zero },
            { mono_assembly_load_from_full, IntPtr.Zero },
            { mono_assembly_get_image, IntPtr.Zero },
            { mono_class_from_name, IntPtr.Zero },
            { mono_class_get_method_from_name, IntPtr.Zero },
            { mono_runtime_invoke, IntPtr.Zero },
            { mono_assembly_close, IntPtr.Zero },
            { mono_image_strerror, IntPtr.Zero },
            { mono_object_get_class, IntPtr.Zero },
            { mono_set_assemblies_path, IntPtr.Zero },
            { mono_assembly_setrootdir, IntPtr.Zero },
            { mono_set_config_dir, IntPtr.Zero },
            { mono_jit_init, IntPtr.Zero },
            { mono_class_get_name, IntPtr.Zero }
        };

        private Memory _memory;

        private IntPtr _rootDomain;
        private IntPtr _il2cppDomain;

        private bool _attach;
        private bool _il2cppattach;

        private readonly IntPtr _handle;

        private IntPtr _mono;
        private IntPtr _gameAssembly;

        private String etcPath;

        public bool Is64Bit { get; private set; }

        public Injector(string processName) : this(Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Equals(processName, StringComparison.OrdinalIgnoreCase))) { }
        public Injector(int processId) : this(Process.GetProcesses().FirstOrDefault(p => p.Id == processId)) { }
        public Injector(Process process)
        {
            etcPath = Path.GetDirectoryName(process.MainModule.FileName) + @"\" + Path.GetFileNameWithoutExtension(process.MainWindowTitle) + @"_Data\il2cpp_data\etc";
            if (process == null)
                throw new InjectorException($"Bad process");

            if ((_handle = Native.OpenProcess(ProcessAccessRights.PROCESS_ALL_ACCESS, false, process.Id)) == IntPtr.Zero)
                throw new InjectorException("Failed to open process", new Win32Exception(Marshal.GetLastWin32Error()));
#if DEBUG
            DllInjector.ShowConsole(_handle);
#endif

            Is64Bit = ProcessUtils.Is64BitProcess(_handle);

            if (!ProcessUtils.GetMonoModule(_handle, out _mono))
            {
                var monoPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                var monoDll = monoPath + @"\mono\mono-2.0-bdwgc.dll";
                /*if (!File.Exists(monoDll))
                {
                    File.WriteAllBytes("mono-2.0-bdwgc.dl_", new WebClient().DownloadData("https://symbolserver.unity3d.com/mono-2.0-bdwgc.dll/5F36619D76c000/mono-2.0-bdwgc.dl_"));
                    var cab = new Microsoft.Deployment.Compression.Cab.CabInfo("mono-2.0-bdwgc.dl_");
                    cab.UnpackFile("mono-2.0-bdwgc.dll", monoDll);
                    File.Delete("mono-2.0-bdwgc.dl_");
                }*/
                DllInjector.Inject(_handle, monoDll);
                if (!ProcessUtils.GetMonoModule(_handle, out _mono))
                    throw new InjectorException("Failed to find mono.dll in the target process");
            }

            if (!ProcessUtils.GetGameAssembly(_handle, out _gameAssembly))
                throw new InjectorException("Failed to find GameAssembly.dll in the target process");

            _memory = new Memory(_handle);
        }

        public Injector(IntPtr processHandle, IntPtr monoModule)
        {
            if ((_handle = processHandle) == IntPtr.Zero)
                throw new ArgumentException("Argument cannot be zero", nameof(processHandle));

            if ((_mono = monoModule) == IntPtr.Zero)
                throw new ArgumentException("Argument cannot be zero", nameof(monoModule));

            Is64Bit = ProcessUtils.Is64BitProcess(_handle);
            _memory = new Memory(_handle);
        }

        public void Dispose()
        {
            _memory.Dispose();
            Native.CloseHandle(_handle);
        }

        private void ObtainMonoExports()
        {
            foreach (ExportedFunction ef in ProcessUtils.GetExportedFunctions(_handle, _mono))
                if (Exports.ContainsKey(ef.Name))
                    Exports[ef.Name] = ef.Address;
            foreach (ExportedFunction ef in ProcessUtils.GetExportedFunctions(_handle, _gameAssembly))
                if (Exports.ContainsKey(ef.Name))
                    Exports[ef.Name] = ef.Address;

            foreach (var kvp in Exports)
                if (kvp.Value == IntPtr.Zero)
                    throw new InjectorException($"Failed to obtain the address of {kvp.Key}()");
        }

        public IntPtr Inject(byte[] rawAssembly, string @namespace, string className, string methodName)
        {
            if (rawAssembly == null)
                throw new ArgumentNullException(nameof(rawAssembly));

            if (rawAssembly.Length == 0)
                throw new ArgumentException($"{nameof(rawAssembly)} cannot be empty", nameof(rawAssembly));

            if (className == null)
                throw new ArgumentNullException(nameof(className));

            if (methodName == null)
                throw new ArgumentNullException(nameof(methodName));

            IntPtr rawImage, assembly, image, @class, method;

            ObtainMonoExports();
            _rootDomain = GetRootDomain();
            _il2cppDomain = GetIl2CppRootDomain();

            rawImage = OpenImageFromData(rawAssembly);
            _attach = true;
            assembly = OpenAssemblyFromImage(rawImage);
            image = GetImageFromAssembly(assembly);
            @class = GetClassFromName(image, @namespace, className);
            method = GetMethodFromName(@class, methodName);
            _il2cppattach = true;
            RuntimeInvoke(method);
            return assembly;
        }

        public void Eject(IntPtr assembly, string @namespace, string className, string methodName)
        {
            if (assembly == IntPtr.Zero)
                throw new ArgumentException($"{nameof(assembly)} cannot be zero", nameof(assembly));

            if (className == null)
                throw new ArgumentNullException(nameof(className));

            if (methodName == null)
                throw new ArgumentNullException(nameof(methodName));

            IntPtr image, @class, method;

            ObtainMonoExports();
            _rootDomain = GetRootDomain();
            _attach = true;
            image = GetImageFromAssembly(assembly);
            @class = GetClassFromName(image, @namespace, className);
            method = GetMethodFromName(@class, methodName);
            RuntimeInvoke(method);
            CloseAssembly(assembly);
        }

        private static void ThrowIfNull(IntPtr ptr, string methodName)
        {
            if (ptr == IntPtr.Zero)
                throw new InjectorException($"{methodName}() returned NULL");
        }

        private IntPtr GetRootDomain()
        {
            IntPtr rootDomain = Execute(Exports[mono_get_root_domain]);
            var qq = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            if (rootDomain == IntPtr.Zero)
                SetupMono(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"\Managed", Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"", etcPath);
            rootDomain = Execute(Exports[mono_get_root_domain]);
            ThrowIfNull(rootDomain, mono_get_root_domain);
            return rootDomain;
        }

        private void SetupMono(string assembliesPath, string rootpath, string configDir)
        {
            Execute(Exports[mono_set_assemblies_path], _memory.AllocateAndWrite(assembliesPath), IntPtr.Zero);
            Execute(Exports[mono_assembly_setrootdir], _memory.AllocateAndWrite(rootpath), IntPtr.Zero);
            Execute(Exports[mono_set_config_dir], _memory.AllocateAndWrite(configDir), IntPtr.Zero);
            Execute(Exports[mono_jit_init], _memory.AllocateAndWrite("MonoLoader"), IntPtr.Zero);
        }

        private IntPtr GetIl2CppRootDomain()
        {
            IntPtr rootDomain = Execute(Exports[il2cpp_domain_get]);
            ThrowIfNull(rootDomain, il2cpp_domain_get);
            return rootDomain;
        }

        private IntPtr OpenImageFromData(byte[] assembly)
        {
            IntPtr statusPtr = _memory.Allocate(4);
            IntPtr rawImage = Execute(Exports[mono_image_open_from_data],
                _memory.AllocateAndWrite(assembly), (IntPtr)assembly.Length, (IntPtr)1, statusPtr);

            MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);
            
            if (status != MonoImageOpenStatus.MONO_IMAGE_OK) {
                IntPtr messagePtr = Execute(Exports[mono_image_strerror], (IntPtr)status);
                string message = _memory.ReadString(messagePtr, 256, Encoding.UTF8);
                throw new InjectorException($"{mono_image_open_from_data}() failed: {message}");
            }

            return rawImage;
        }

        private IntPtr OpenAssemblyFromImage(IntPtr image)
        {
            IntPtr statusPtr = _memory.Allocate(4);
            IntPtr assembly = Execute(Exports[mono_assembly_load_from_full],
                image, _memory.AllocateAndWrite(new byte[1]), statusPtr, IntPtr.Zero);

            MonoImageOpenStatus status = (MonoImageOpenStatus)_memory.ReadInt(statusPtr);

            if (status != MonoImageOpenStatus.MONO_IMAGE_OK) {
                IntPtr messagePtr = Execute(Exports[mono_image_strerror], (IntPtr)status);
                string message = _memory.ReadString(messagePtr, 256, Encoding.UTF8);
                throw new InjectorException($"{mono_assembly_load_from_full}() failed: {message}");
            }

            return assembly;
        }

        private IntPtr GetImageFromAssembly(IntPtr assembly)
        {
            IntPtr image = Execute(Exports[mono_assembly_get_image], assembly);
            ThrowIfNull(image, mono_assembly_get_image);
            return image;
        }

        private IntPtr GetClassFromName(IntPtr image, string @namespace, string className)
        {
            IntPtr @class = Execute(Exports[mono_class_from_name],
                image, _memory.AllocateAndWrite(@namespace), _memory.AllocateAndWrite(className));
            ThrowIfNull(@class, mono_class_from_name);
            return @class;
        }

        private IntPtr GetMethodFromName(IntPtr @class, string methodName)
        {
            IntPtr method = Execute(Exports[mono_class_get_method_from_name],
                @class, _memory.AllocateAndWrite(methodName), IntPtr.Zero);
            ThrowIfNull(method, mono_class_get_method_from_name);
            return method;
        }

        private string GetClassName(IntPtr monoObject)
        {
            IntPtr @class = Execute(Exports[mono_object_get_class], monoObject);
            ThrowIfNull(@class, mono_object_get_class);
            IntPtr className = Execute(Exports[mono_class_get_name], @class);
            ThrowIfNull(className, mono_class_get_name);
            return _memory.ReadString(className, 256, Encoding.UTF8);
        }

        private string ReadMonoString(IntPtr monoString)
        {
            int len = _memory.ReadInt(monoString + (Is64Bit ? 0x10 : 0x8));
            return _memory.ReadUnicodeString(monoString + (Is64Bit ? 0x14 : 0xC), len * 2);
        }

        private void RuntimeInvoke(IntPtr method)
        {
            IntPtr excPtr = Is64Bit ? _memory.AllocateAndWrite((long)0) : _memory.AllocateAndWrite(0);

            IntPtr result = Execute(Exports[mono_runtime_invoke],
                method, IntPtr.Zero, IntPtr.Zero, excPtr);

            IntPtr exc = (IntPtr)_memory.ReadLong(excPtr);

            if (exc != IntPtr.Zero)
            {
                string className = GetClassName(exc);
                string message = ReadMonoString((IntPtr)_memory.ReadLong(exc + (Is64Bit ? 0x20 : 0x10)));
                throw new InjectorException($"The managed method threw an exception: ({className}) {message}");
            }
        }

        private void CloseAssembly(IntPtr assembly)
        {
            IntPtr result = Execute(Exports[mono_assembly_close], assembly);
            ThrowIfNull(result, mono_assembly_close);
        }

        private IntPtr Execute(IntPtr address, params IntPtr[] args)
        {
            IntPtr retValPtr = Is64Bit
                ? _memory.AllocateAndWrite((long)0)
                : _memory.AllocateAndWrite(0);

            byte[] code = Assemble(address, retValPtr, args);
            IntPtr alloc = _memory.AllocateAndWrite(code);

            IntPtr thread = Native.CreateRemoteThread(
                _handle, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out _);

            if (thread == IntPtr.Zero)
                throw new InjectorException("Failed to create a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

            WaitResult result = Native.WaitForSingleObject(thread, -1);

            if (result == WaitResult.WAIT_FAILED)
                throw new InjectorException("Failed to wait for a remote thread", new Win32Exception(Marshal.GetLastWin32Error()));

            IntPtr ret = Is64Bit
                ? (IntPtr)_memory.ReadLong(retValPtr)
                : (IntPtr)_memory.ReadInt(retValPtr);

            if ((long)ret == 0x00000000C0000005)
                throw new InjectorException($"An access violation occurred while executing {Exports.First(e => e.Value == address).Key}()");

            return ret;
        }

        private byte[] Assemble(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            return Is64Bit
                ? Assemble64(functionPtr, retValPtr, args)
                : Assemble86(functionPtr, retValPtr, args);
        }

        private byte[] Assemble86(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            Assembler asm = new Assembler();

            if (_attach) {
                asm.Push(_rootDomain);
                asm.MovEax(Exports[mono_thread_attach]);
                asm.CallEax();
                asm.AddEsp(4);
            }

            for (int i = args.Length - 1; i >= 0; i--)
                asm.Push(args[i]);

            asm.MovEax(functionPtr);
            asm.CallEax();
            asm.AddEsp((byte)(args.Length * 4));
            asm.MovEaxTo(retValPtr);
            asm.Return();

            return asm.ToByteArray();
        }

        private byte[] Assemble64(IntPtr functionPtr, IntPtr retValPtr, IntPtr[] args)
        {
            Assembler asm = new Assembler();

            asm.SubRsp(40);

            if (_attach)
            {
                asm.MovRax(Exports[mono_thread_attach]);
                asm.MovRcx(_rootDomain);
                asm.CallRax();
            }
            if (_il2cppattach)
            {
                asm.MovRax(Exports[il2cpp_thread_attach]);
                asm.MovRcx(_il2cppDomain);
                asm.CallRax();
            }

            asm.MovRax(functionPtr);

            for (int i = 0; i < args.Length; i++) {
                switch (i) {
                    case 0:
                        asm.MovRcx(args[i]);
                        break;
                    case 1:
                        asm.MovRdx(args[i]);
                        break;
                    case 2:
                        asm.MovR8(args[i]);
                        break;
                    case 3:
                        asm.MovR9(args[i]);
                        break;
                }
            }

            asm.CallRax();
            asm.AddRsp(40);
            asm.MovRaxTo(retValPtr);
            asm.Return();

            return asm.ToByteArray();
        }
    }

    
    public class DllInjector
    {
        [DllImport("kernel32")] static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32")] static extern IntPtr GetModuleHandle(string lpModuleName);
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        public static void Inject(IntPtr procHandle, String dllName)
        {
            IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), 0x3000, 4);
            WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf<char>()), out UIntPtr bytesWritten);
            var t = CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
            Native.WaitForSingleObject(t, -1);
        }
        public static void ShowConsole(IntPtr procHandle)
        {
            IntPtr allocConsoleAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "AllocConsole");
            var t = CreateRemoteThread(procHandle, IntPtr.Zero, 0, allocConsoleAddr, IntPtr.Zero, 0, IntPtr.Zero);
            Native.WaitForSingleObject(t, -1);
        }
    }
}
