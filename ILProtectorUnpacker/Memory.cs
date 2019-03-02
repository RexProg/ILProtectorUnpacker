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
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        internal static unsafe void Hook(MethodBase from, MethodBase to)
        {
            var addressSrc = GetAddress(from);
            var addressDst = GetAddress(to);

            //Console.WriteLine(addressSrc.ToString("X8"));
            //Console.WriteLine(addressDst.ToString("X8"));
            //Console.WriteLine("Press any key to continue...");
            //Console.ReadKey(true);

            // skip first 6 bytes
            // 0x55,         push ebp
            // 0x8B, 0xEC,   mov ebp, esp
            // 0x57,         push edi
            // 0x56,         push esi
            // 0x50,         push eax
            addressSrc += 6;

            byte[] bytesBefore =
            {
                0x58,               // pop eax
                0x5E,               // pop esi
                0x5F,               // pop eax
                // pop ebp alternative
                0x8B, 0x2C, 0x24,   // mov ebp, dword ptr [esp]
                0x83, 0xC4, 0x04    // add esp, 4
            };
            byte[] jmpBytes;

            if (IntPtr.Size == 4)
            {
                jmpBytes = new byte[]
                {
                    0x33, 0xC0, // xor eax, eax
                    0x85, 0xC0, // test eax, eax
                    0x0F, 0x84, // jz
                    0x00, 0x00, 0x00, 0x00,
                    0xC3        // ret
                };
                fixed (byte* p = jmpBytes)
                {
                    *(int*)(p + 6) = addressDst.ToInt32() - addressSrc.ToInt32() - (bytesBefore.Length + jmpBytes.Length - 1);
                }
            }
            else if (IntPtr.Size == 8)
            {
                jmpBytes = new byte[]
                {
                    // movabs r11, target
                    0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    // jmp r11
                    0x41, 0xFF, 0xE3
                };
                fixed (byte* p = jmpBytes)
                {
                    *(long*)(p + 2) = addressDst.ToInt64();
                }
            }
            else
            {
                throw new NotImplementedException();
            }

            byte[] writeBytes = new byte[bytesBefore.Length + jmpBytes.Length];
            Array.Copy(bytesBefore, writeBytes, bytesBefore.Length);
            Array.Copy(jmpBytes, 0, writeBytes, bytesBefore.Length, jmpBytes.Length);

            VirtualProtect(addressSrc, (uint)writeBytes.Length, PAGE_EXECUTE_READWRITE, out var flOldProtect);
            Marshal.Copy(writeBytes, 0, addressSrc, writeBytes.Length);
            VirtualProtect(addressSrc, (uint)writeBytes.Length, flOldProtect, out _);
        }

        public static IntPtr GetAddress(MethodBase methodBase)
        {
            RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
            return methodBase.MethodHandle.GetFunctionPointer();
        }
    }
}