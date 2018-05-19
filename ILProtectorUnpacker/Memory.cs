#region using

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#endregion

namespace ILProtectorUnpacker
{
    internal class Memory
    {
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect,
            out uint lpflOldProtect);

        internal static unsafe void Hook(MethodBase from, MethodBase to)
        {
            var address = GetAddress(from);
            var address2 = GetAddress(to);
            uint flNewProtect;
            VirtualProtect(address, (IntPtr) 5, 64u, out flNewProtect);
            if (IntPtr.Size == 8)
            {
                var ptr = (byte*) address.ToPointer();
                *ptr = 73;
                ptr[1] = 187;
                *(long*) (ptr + 2) = address2.ToInt64();
                ptr[10] = 65;
                ptr[11] = byte.MaxValue;
                ptr[12] = 227;
            }
            else if (IntPtr.Size == 4)
            {
                var ptr2 = (byte*) address.ToPointer();
                *ptr2 = 233;
                *(long*) (ptr2 + 1) = address2.ToInt32() - address.ToInt32() - 5;
                ptr2[5] = 195;
            }

            uint num;
            VirtualProtect(address, (IntPtr) 5, flNewProtect, out num);
        }

        public static IntPtr GetAddress(MethodBase methodBase)
        {
            RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
            return methodBase.MethodHandle.GetFunctionPointer();
        }
    }
}