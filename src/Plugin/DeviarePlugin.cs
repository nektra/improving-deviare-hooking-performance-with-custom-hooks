using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Nektra.Deviare2;

//DO NOT PUT THE CLASS INSIDE A NAMESPACE
public class DeviarePlugin
{
    private NktSpyMgr _spyMgr = null;
    private KnuthMorrisPratt _kmp = new KnuthMorrisPratt("malware");

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);


    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CancelIo(IntPtr hFile);

    [DllImport("kernel32.dll")]
    static extern bool LockFile(IntPtr hFile, uint dwFileOffsetLow, uint
       dwFileOffsetHigh, uint nNumberOfBytesToLockLow, uint
       nNumberOfBytesToLockHigh);

    public DeviarePlugin()
    {
        return;
    }

    public int OnLoad()
    {
        return 0;
    }

    public void OnUnload()
    {
        System.Diagnostics.Trace.WriteLine("DeviarePlugin::OnUnload called");
        return;
    }

    public int OnHookAdded(INktHookInfo hookInfo, int chainIndex)
    {
        System.Diagnostics.Trace.WriteLine("DeviarePlugin::OnHookAdded called [Hook: " + hookInfo.FunctionName + " @ 0x" + hookInfo.Address.ToString("X") + " / Chain:" + chainIndex.ToString() + "]");
        return 0;
    }

    public int OnHookRemoved(INktHookInfo hookInfo, int chainIndex)
    {
        System.Diagnostics.Trace.WriteLine("DeviarePlugin::OnHookAdded called [Hook: " + hookInfo.FunctionName + " @ 0x" + hookInfo.Address.ToString("X") + " / Chain:" + chainIndex.ToString() + "]");
        return 0;
    }

    byte[] GetValue(uint pid, INktParam paramData, INktParam paramSize, bool sizeAndTypeArePtr)
    {
        byte[] buffer = null;
        uint valueSize;

        if (sizeAndTypeArePtr)
        {
            if (paramSize.IsNullPointer == false)
            {
                valueSize = paramSize.Evaluate().ULongVal;
            }
            else
            {
                valueSize = 0;
            }
        }
        else
        {
            valueSize = paramSize.ULongVal;
        }

        if (paramData.IsNullPointer == false)
        {
            //if (paramData.PointerVal != IntPtr.Zero)
            if (!paramData.PointerVal.Equals(IntPtr.Zero))
            {
                INktProcessMemory procMem = _spyMgr.ProcessMemoryFromPID((int)pid);
                //var buffer = new byte[valueSize];
                buffer = new byte[valueSize];

                GCHandle pinnedBuffer = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                IntPtr pDest = pinnedBuffer.AddrOfPinnedObject();
                //Int64 bytesReaded = procMem.ReadMem(pDest, paramData.PointerVal, (IntPtr)valueSize).ToInt64();
                //Int64 bytesReaded = procMem.ReadMem((int) pDest, (int)paramData.PointerVal, (int) valueSize).ToInt64();
                Int64 bytesReaded = procMem.ReadMem(pDest, paramData.PointerVal, (IntPtr)valueSize).ToInt64();
                pinnedBuffer.Free();

                /*                    valueData = "";
                                    for (int i = 0; i < bytesReaded; i++)
                                    {
                                        if (i != 0)
                                            valueData += " ";
                                        valueData += Convert.ToByte(buffer[i]).ToString("X2");
                                    }*/
            }
        }

        return buffer;
    }
    public int MapViewOfFileHook(INktHookInfo hookInfo, int chainIndex, INktHookCallInfoPlugin callInfo)
    {
        IntPtr address = callInfo.Result().PointerVal;

        byte[] buffer = new byte[1];

        Marshal.Copy(address, buffer, 0, 1);

        char[] chars = System.Text.Encoding.UTF8.GetString(buffer).ToCharArray();

        Trace.Write(chars);


        return 0;
    }

    private void CreateFileWHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
    }

    private void ReadFileHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
    }

    private void CloseHandleHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
    }

    private void CreateFileMappingWHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
    }

    private bool LookForMalware(IntPtr map, ulong length)
    {
            if(!map.Equals(IntPtr.Zero) && length != 0)
            {
                int index = this._kmp.Search(map, (uint) length);

                if (index != -1)
                    return true;

                Debug.WriteLine(String.Format("length = {0} KMP returned = {1}", length, index));
            }


        return false;
    }


    private void MapViewOfFileHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
        IntPtr map = callInfo.Result().PointerVal;
        IntPtr length = callInfo.Params().GetAt(4).PointerVal;
        bool is_malware = LookForMalware(map, (ulong)length); // assuming that length is int in this example. So, mapped files greater than 2^32 - 1 will not work. Also indices on native arrays are limited to int.

        if (is_malware)
        {
            callInfo.AddByte("has_malware", 1);
            callInfo.Result().PointerVal = IntPtr.Zero;
            callInfo.LastError = 2;
            callInfo.SkipCall();
        } else {
            callInfo.AddByte("has_malware", 0);
        }
    }

    private void OpenFileMappingWHook(INktHookInfo hookInfo, INktHookCallInfoPlugin callInfo)
    {
    }


    public int OnFunctionCall(INktHookInfo hookInfo, int chainIndex, INktHookCallInfoPlugin callInfo)
    {
        if (hookInfo.FunctionName == "MapViewOfFile")
        {
            MapViewOfFileHook(hookInfo, callInfo);
        }

        return 0;
    }
}
