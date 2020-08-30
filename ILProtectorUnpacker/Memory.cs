#region using

using System;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#endregion

namespace ILProtectorUnpacker
{
    internal static class Memory
    {
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        internal static void Hook(MethodBase from, MethodBase to)
        {
            var addressSrc = GetAddress(from);
            var addressDst = GetAddress(to);

            //Console.WriteLine(addressSrc.ToString("X8"));
            //Console.WriteLine(addressDst.ToString("X8"));
            //Console.WriteLine("Press any key to continue...");
            //Console.ReadKey(true);

            byte[] hookBytes;

            switch (IntPtr.Size)
            {
                case 4:
                    // skip first 6 bytes
                    // 0x55,         push ebp
                    // 0x8B, 0xEC,   mov ebp, esp
                    // 0x57,         push edi
                    // 0x56,         push esi
                    // 0x50,         push eax
                    addressSrc += 6;

                    hookBytes = BuildFinalHookBytes(addressSrc, addressDst, new byte[]
                    {
                        0x58, // pop eax
                        0x5E, // pop esi
                        0x5F, // pop edi

                        // pop ebp alternative
                        0x8B, 0x2C, 0x24, // mov ebp, dword ptr [esp]
                        0x83, 0xC4, 0x04, // add esp, 4

                        0x33, 0xC0, // xor eax, eax
                        0x85, 0xC0, // test eax, eax
                        0x0F, 0x84, // jz
                        0x00, 0x00, 0x00, 0x00, // address placeholder
                        0xC3 // ret
                    });

                    break;

                case 8:
                    // skip first 3 bytes
                    // 0x57,         push rdi
                    // 0x55,         push rsi
                    // 0x53,         push rbx
                    addressSrc += 3;

                    hookBytes = BuildFinalHookBytes(addressSrc, addressDst, new byte[]
                    {
                        0x5B, // pop rbx
                        0x5E, // pop rsi
                        0x5F, // pop rdi

                        0x49, 0xBB, // movabs r11
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address placeholder
                        0x41, 0xFF, 0xE3, // jmp r11
                        0xC3 // ret
                    });

                    break;

                default:
                    throw new NotImplementedException();
            }

            Write(addressSrc, hookBytes);
        }

        public static void SimpleHook(MethodBase from, MethodBase to)
        {
            var addressSrc = GetAddress(from);
            var addressDst = GetAddress(to);
            SimpleHook(addressSrc, addressDst);
        }

        public static void SimpleHook(IntPtr src, IntPtr dst)
        {
            var hookBytes = IntPtr.Size == 4 ? new byte[] { 0xE9 } : new byte[] { 0x48, 0xB8 };
            hookBytes = hookBytes.Concat(Enumerable.Repeat((byte)0x00, IntPtr.Size)).ToArray();
            if (IntPtr.Size == 8)
            {
                hookBytes = hookBytes.Concat(new byte[] { 0xFF, 0xE0 }).ToArray();
            }
            hookBytes = BuildFinalHookBytes(src, dst, hookBytes);
            Write(src, hookBytes);
        }

        public static void Write(IntPtr addr, byte[] bytes, out byte[] originalBytes)
        {
            originalBytes = new byte[bytes.Length];
            VirtualProtect(addr, (uint)bytes.Length, PAGE_EXECUTE_READWRITE, out var flOldProtect);
            Marshal.Copy(addr, originalBytes, 0, originalBytes.Length);
            Marshal.Copy(bytes, 0, addr, bytes.Length);
            VirtualProtect(addr, (uint)bytes.Length, flOldProtect, out _);
        }

        public static void Write(IntPtr addr, byte[] bytes)
        {
            VirtualProtect(addr, (uint)bytes.Length, PAGE_EXECUTE_READWRITE, out var flOldProtect);
            Marshal.Copy(bytes, 0, addr, bytes.Length);
            VirtualProtect(addr, (uint)bytes.Length, flOldProtect, out _);
        }

        /// <exception cref="T:System.ArgumentOutOfRangeException"></exception>
        /// <exception cref="T:System.NotImplementedException"></exception>
        private static byte[] BuildFinalHookBytes(IntPtr addrSrc, IntPtr addrDst, byte[] hookBytes)
        {
            var hookBytesCopy = hookBytes.ToArray();

            var addrPlaceholderBytes = Enumerable.Repeat((byte)0x00, IntPtr.Size).ToArray();
            var startIndexAddrPlaceholder = FindSequence(hookBytes, addrPlaceholderBytes);

            if (startIndexAddrPlaceholder == -1)
            {
                throw new ArgumentOutOfRangeException(nameof(startIndexAddrPlaceholder));
            }

            byte[] jmpAddrBytes;
            switch (IntPtr.Size)
            {
                case 4:
                    var jmpAddr = addrDst.ToInt32() - addrSrc.ToInt32() - (startIndexAddrPlaceholder + addrPlaceholderBytes.Length);
                    jmpAddrBytes = BitConverter.GetBytes(jmpAddr);
                    break;
                case 8:
                    jmpAddrBytes = BitConverter.GetBytes(addrDst.ToInt64());
                    break;
                default:
                    throw new NotImplementedException();
            }

            for (var i = 0; i < jmpAddrBytes.Length; i++)
            {
                hookBytesCopy[startIndexAddrPlaceholder + i] = jmpAddrBytes[i];
            }

            return hookBytesCopy;
        }

        public static int FindSequence(byte[] source, byte[] seq)
        {
            var start = -1;
            for (var i = 0; i < source.Length - seq.Length + 1 && start == -1; i++)
            {
                var j = 0;
                for (; j < seq.Length && source[i + j] == seq[j]; j++) { }
                if (j == seq.Length) start = i;
            }
            return start;
        }

        private static IntPtr GetDynamicMethodAddress(DynamicMethod dynamicMethod)
        {
            var type = dynamicMethod.GetType();
            var fieldInfo = type.GetField("m_method", BindingFlags.Instance | BindingFlags.NonPublic);
            if (fieldInfo == null)
            {
                fieldInfo = type.GetField("m_methodHandle", BindingFlags.Instance | BindingFlags.NonPublic);
            }
            var runtimeMethodInfoStub = fieldInfo?.GetValue(dynamicMethod);
            if (runtimeMethodInfoStub == null)
            {
                return IntPtr.Zero;
            }
            var runtimeMethodHandleInternal = runtimeMethodInfoStub.GetType().GetField("m_value", BindingFlags.Instance | BindingFlags.Public).GetValue(runtimeMethodInfoStub);
            var getFunctionPointer = typeof(RuntimeMethodHandle).GetMethod(nameof(RuntimeMethodHandle.GetFunctionPointer), BindingFlags.Static | BindingFlags.NonPublic);
            var ptr = (IntPtr)getFunctionPointer.Invoke(null, new[] { runtimeMethodHandleInternal });
            return ptr;
        }

        public static IntPtr GetAddress(DynamicMethod dynamicMethod)
        {
            var ptr = GetDynamicMethodAddress(dynamicMethod);
            if (ptr == IntPtr.Zero)
            {
                var @params = Enumerable.Repeat((object)null, dynamicMethod.GetParameters().Length).ToArray();
                try
                {
                    dynamicMethod.Invoke(null, @params);
                }
                catch
                {
                    // ignored
                }
            }
            ptr = GetDynamicMethodAddress(dynamicMethod);
            return ptr;
        }

        public static IntPtr GetAddress(MethodBase methodBase)
        {
            if (methodBase is DynamicMethod dynamicMethod)
            {
                return GetAddress(dynamicMethod);
            }
            RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
            return methodBase.MethodHandle.GetFunctionPointer();
        }
    }
}