using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Nektra.Deviare2;
using System.Windows.Forms;
using System.IO;

namespace Deviare_Custom_Handler_Sample
{
    class HookingManager
    {

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
        uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [Flags]
        public enum DuplicateOptions : uint
        {
        DUPLICATE_CLOSE_SOURCE = (0x00000001),// Closes the source handle. This occurs regardless of any error status returned.
        DUPLICATE_SAME_ACCESS = (0x00000002), //Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            FileMapAccess dwDesiredAccess,
            UInt32 dwFileOffsetHigh,
            UInt32 dwFileOffsetLow,
            UIntPtr dwNumberOfBytesToMap);

        [Flags]
        public enum FileMapAccess : uint
        {
            FileMapCopy = 0x0001,
            FileMapWrite = 0x0002,
            FileMapRead = 0x0004,
            FileMapAllAccess = 0x001f,
            FileMapExecute = 0x0020,
        }

        [DllImport("kernel32.dll")]
        static extern uint LocalSize(IntPtr hMem);

        List<NktHook> hooks = new List<NktHook>();
        private NktSpyMgr _spyMgr = null;
        string _custom_handler_path = "";
        string _custom_handler_relative_path = @"..\..\..\Plugin\bin\Debug\MyRegistryPlugin.dll";

        KnuthMorrisPratt _kmp = new KnuthMorrisPratt("thisismalware"); /* this must be changed to using one instance per handler */
        bool _use_deviare_custom_hook_plugin = false;

        public HookingManager()
        {
            string current_directory = Directory.GetCurrentDirectory();
            this._custom_handler_path = Path.Combine(current_directory, this._custom_handler_relative_path);

            this._spyMgr = new NktSpyMgr();
            this._spyMgr.Initialize();
            this._spyMgr.OnFunctionCalled += new DNktSpyMgrEvents_OnFunctionCalledEventHandler(_spyMgr_OnFunctionCalled);
        }


        private bool LookForMalware(IntPtr source_process_handle, IntPtr source_handle, uint length)
        {
            //BOOL WINAPI DuplicateHandle(
            //  _In_   HANDLE hSourceProcessHandle,
            //  _In_   HANDLE hSourceHandle,
            //  _In_   HANDLE hTargetProcessHandle,
            //  _Out_  LPHANDLE lpTargetHandle,
            //  _In_   DWORD dwDesiredAccess,
            //  _In_   BOOL bInheritHandle,
            //  _In_   DWORD dwOptions
            //);

            IntPtr target_process_handle = Process.GetCurrentProcess().Handle;
            IntPtr target_handle = IntPtr.Zero;

            bool is_success = DuplicateHandle(source_process_handle, source_handle, target_process_handle, out target_handle, (uint)0, true, (uint)DuplicateOptions.DUPLICATE_SAME_ACCESS);

            Debug.WriteLine(String.Format("DuplicateHandle :: is_success = {0} with target handle = {1}", is_success, (uint) target_handle));

            if (is_success)
            {
                //  LPVOID WINAPI MapViewOfFile(
                //  _In_  HANDLE hFileMappingObject,
                //  _In_  DWORD dwDesiredAccess,
                //  _In_  DWORD dwFileOffsetHigh,
                //  _In_  DWORD dwFileOffsetLow,
                //  _In_  SIZE_T dwNumberOfBytesToMap
                //);

                //IntPtr map = (IntPtr) MapViewOfFile(target_handle, FileMapAccess.FileMapAllAccess, (uint) 0, (uint) 0, (UIntPtr) 0);
                IntPtr map = (IntPtr)MapViewOfFile(target_handle, FileMapAccess.FileMapRead, (uint)0, (uint)0, (UIntPtr)0);

                Debug.WriteLine(String.Format("DuplicateHandle :: address mapped = {0}", map));

                if (map.Equals(IntPtr.Zero))
                {
                    //Debug.WriteLine(String.Format("GetLastError = {0}", 
                } else {

                    byte[] buffer = new byte[20];

                    Marshal.Copy(map, buffer, 0, 20);

                    string s = System.Text.Encoding.UTF8.GetString(buffer);
                    //uint length = LocalSize(map);

                    int index = this._kmp.Search(map, length);

                    if (index != -1)
                        return true;

                    Debug.WriteLine(String.Format("Buffer = {0} length = {1} KMP returned = {2}", s, length, index));
                }


            }

            return false;
        }

        private void MapViewOfFileCustomHook(NktHook Hook, NktProcess proc, NktHookCallInfo callInfo)
        {
            if (callInfo.CustomParams().Count == 1)
            {
                byte has_malware = callInfo.CustomParams().GetAt(0).ByteVal;

                Debug.WriteLine(String.Format("MapViewOfFileCustomHook:: with has_malware = {0}", has_malware));
            }
        }

        private void MapViewOfFileHook(NktHook Hook, NktProcess proc, NktHookCallInfo callInfo)
        {
            bool is_malware = false;

            IntPtr maphandle = callInfo.Params().GetAt(0).PointerVal;
            IntPtr address = callInfo.Result().PointerVal;
            IntPtr length = callInfo.Params().GetAt(4).PointerVal;
            Debug.WriteLine(String.Format("MapViewOfFile:: with maphandle = {0} dwNumberOfBytesToMap = {1}", maphandle, length));

            IntPtr process_handle = callInfo.Process().Handle(0x1FFFF);

            is_malware = LookForMalware(process_handle, (IntPtr)maphandle, (uint)length); // assuming that length is int in this example. So, mapped files greater than 2^32 - 1 will not work. Also Marshal.ReadByte is limited to int.



            if (is_malware)
            {
                callInfo.Result().PointerVal = IntPtr.Zero;
                callInfo.LastError = 2;
                callInfo.SkipCall();
            }
        }

        void _spyMgr_OnFunctionCalled(NktHook Hook, NktProcess proc, NktHookCallInfo callInfo)
        {
            if (Hook.FunctionName == "kernel32.dll!MapViewOfFile")
            {
                if (this._use_deviare_custom_hook_plugin)
                    MapViewOfFileCustomHook(Hook, proc, callInfo);
                else
                    MapViewOfFileHook(Hook, proc, callInfo);
            }
        }

        public void Hook(bool use_deviare_custom_hook_plugin)
        {
            this._use_deviare_custom_hook_plugin = use_deviare_custom_hook_plugin;
            string[] functions = {"kernel32.dll!MapViewOfFile"};

            Nektra.Deviare2.eNktHookFlags flags = 0;

            flags |= eNktHookFlags.flgAutoHookChildProcess;
            flags |= eNktHookFlags.flgOnlyPostCall;

            if(_use_deviare_custom_hook_plugin)
                flags |= eNktHookFlags.flgAsyncCallbacks;

            foreach(var function in functions) {
                NktHook a_hook = this._spyMgr.CreateHook(function, (int) flags);
                if (this._use_deviare_custom_hook_plugin)
                    a_hook.AddCustomHandler(this._custom_handler_path, (int)Nektra.Deviare2.eNktHookCustomHandlerFlags.flgChDontCallIfLoaderLocked);

                a_hook.Hook(true);
                hooks.Add(a_hook);
            }

            NktProcessesEnum processes = this._spyMgr.Processes();
            NktProcess process = processes.First();

            while (process != null)
            {
                if (process.Name.Equals("notepad.exe", StringComparison.InvariantCultureIgnoreCase))
                {
                    foreach (var hook in hooks)
                        hook.Attach(process, true);
                }
                Debug.WriteLine(String.Format("process.Name = {0} process.PlatformBits = {1}", process.Name, process.PlatformBits));
                process = processes.Next();
            }
        }
    }
}
