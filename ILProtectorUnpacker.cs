//css_co /unsafe
//css_ref dnlib.dll
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;
using System.IO;
using System.Threading;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

class Script
{
    public static AssemblyWriter assemblyWriter;
    public static Assembly assembly;
    public static MethodDef currentMethod;
    public static StackFrame[] mainFrames;
    public static List<TypeDef> junkType = new List<TypeDef>();

    [STAThread]
    static public void Main(string[] args)
    {
        try
        {
            Console.BackgroundColor = ConsoleColor.White;
            Console.ForegroundColor = ConsoleColor.Black;
            Console.WriteLine("*********************************");
            Console.WriteLine("***                           ***");
            Console.WriteLine("***    ILProtector Unpacker   ***");
            Console.WriteLine("***     Coded By RexProg      ***");
            Console.WriteLine("***                           ***");
            Console.WriteLine("*********************************");
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[?] Enter Your Program Path : ");
            Console.ForegroundColor = ConsoleColor.Red;

            var path = Console.ReadLine();

            if (path == string.Empty)
                return;
            if (path.StartsWith("\"") && path[path.Length - 1] == '"')
                path = path.Substring(1, path.Length - 2);

            if (!File.Exists(path))
            {
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("[!] File not found");
                Console.WriteLine("[!] Press key to exit...");
                Console.Read();
                return;
            }
            Console.ForegroundColor = ConsoleColor.DarkRed;

            assemblyWriter = new AssemblyWriter(path);
            assembly = Assembly.LoadFrom(path);
            Console.WriteLine("[+] Wait...");

            mainFrames = new StackTrace().GetFrames();

            Memory.Hook(typeof(StackTrace).GetMethod("CaptureStackTrace", BindingFlags.Instance | BindingFlags.NonPublic), typeof(Script).GetMethod("Hook3", BindingFlags.Instance | BindingFlags.Public));

            var types = assemblyWriter.moduleDef.GetTypes();
            var list = (types as IList<TypeDef>) ?? types.ToList<TypeDef>();

            var globalType = assemblyWriter.moduleDef.GlobalType;

            var fieldMDToken = 0;

            foreach (FieldDef fieldDef in globalType.Fields)
            {
                if (fieldDef.Name == "Invoke")
                    fieldMDToken = fieldDef.MDToken.ToInt32();
            }
            if (fieldMDToken == 0)
                Console.WriteLine("[!] Couldn't find Invoke");

            var fieldValue = assembly.Modules.FirstOrDefault<Module>().ResolveField(fieldMDToken).GetValue(null);

            var method = fieldValue.GetType().GetMethod("Invoke");

            if (method == null)
                Console.WriteLine("[!] Couldn't find InvokeMethod");
            InvokeDelegates(list, method, fieldValue);

            new StringDecrypter(assembly).ReplaceStrings(list);

            foreach (var typeDef in junkType)
            {
                typeDef.DeclaringType.NestedTypes.Remove(typeDef);
            }

            MethodDef methodDef = globalType.FindStaticConstructor();

            if (methodDef.HasBody)
            {
                var startIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(inst =>
                (inst.OpCode == OpCodes.Call
                && ((IMethod)inst.Operand).Name == "GetIUnknownForObject"))) - 2;

                var endindex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(inst =>
                (inst.OpCode == OpCodes.Call
                && ((IMethod)inst.Operand).Name == "Release"))) + 2;

                methodDef.Body.ExceptionHandlers.Remove(methodDef.Body.ExceptionHandlers.FirstOrDefault(exh => exh.HandlerEnd == methodDef.Body.Instructions[endindex + 1]));

                for (int i = startIndex; i <= endindex; i++)
                    methodDef.Body.Instructions.Remove(methodDef.Body.Instructions[startIndex]);
            }

            foreach (var meth in globalType.Methods.Where(met => (met.ImplMap?.Module.Name.ToString() == "Protect32.dll" || met.ImplMap?.Module.Name.ToString() == "Protect64.dll")).ToList())
                globalType.Remove(meth);

            var invokeField = globalType.Fields.FirstOrDefault(fld => fld.Name == "Invoke");
            assemblyWriter.moduleDef.Types.Remove(invokeField.FieldType.ToTypeDefOrRef().ResolveTypeDef());
            globalType.Fields.Remove(invokeField);

            assemblyWriter.Save();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("[!] Program Unpacked");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Exception :\n" + ex.Message);
        }
        Console.WriteLine("[!] Press key to exit...");
        Console.Read();
    }

    private static void InvokeDelegates(IList<TypeDef> typeDefs, MethodInfo invokeMethod, object invokeField)
    {
        foreach (TypeDef typeDef in typeDefs)
        {
            foreach (MethodDef methodDef in typeDef.Methods)
            {
                if (!(methodDef.Module.Name != assembly.ManifestModule.ScopeName) && methodDef.HasBody && methodDef.Body.Instructions.Count > 2 && methodDef.Body.Instructions[0].OpCode == OpCodes.Ldsfld && methodDef.Body.Instructions[0].Operand.ToString().Contains("Invoke") && methodDef.Body.Instructions[1].IsLdcI4())
                {
                    currentMethod = methodDef;

                    var _MDToken = ((IType)methodDef.Body.Instructions[3].Operand).MDToken.ToInt32();
                    junkType.Add(typeDef.NestedTypes.FirstOrDefault(net => net.MDToken.ToInt32() == _MDToken));

                    object method = invokeMethod.Invoke(invokeField, new object[] { (int)methodDef.Body.Instructions[1].Operand });

                    try
                    {
                        var dynamicMethodBodyReader = new DynamicMethodBodyReader(assemblyWriter.moduleDef, method);
                        dynamicMethodBodyReader.Read();
                        var method2 = dynamicMethodBodyReader.GetMethod();
                        assemblyWriter.WriteMethod(method2);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error in Read(): " + ex.Message + "\nMethod : " + method.ToString());
                    }
                }
            }
        }
    }

    public StackFrame Hook(int num)
    {
        StackFrame[] frames = new StackTrace().GetFrames();

        for (int i = 0; i < frames.Length; i++)
        {
            MethodBase method = frames[i].GetMethod();

            if (num == 0 && method.ToString().StartsWith("System.Delegate ("))
            {
                return frames[i];
            }
            if (num == 1 && method.ToString().StartsWith("System.Delegate ("))
            {
                MethodBase value = assembly.Modules.FirstOrDefault<Module>().ResolveMethod(currentMethod.MDToken.ToInt32());
                typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(frames[i + 1], value);
                return frames[i + 1];
            }
        }
        return null;
    }

    public void Hook2(MethodBase mb)
    {
        if (mb.Name == "InvokeMethod")
            typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(this, assembly.Modules.FirstOrDefault<Module>().ResolveMethod(currentMethod.MDToken.ToInt32()));
        else
            typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(this, mb);
    }

    public void Hook3(int iSkip, bool fNeedFileInfo, Thread targetThread, Exception e)
    {
        ///////////////////////////////////////////////////////////////////////////////////////////////
        //    FrameCount    |                2	                 |               int                 //
        //  METHODS_TO_SKIP |                0	                 |               int                 //
        //      frames      | {System.Diagnostics.StackFrame[6]} |  System.Diagnostics.StackFrame[]  //
        // m_iMethodsToSkip	|                4	                 |               int                 //
        //  m_iNumOfFrames  |                2	                 |               int                 //
        ///////////////////////////////////////////////////////////////////////////////////////////////
        typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(mainFrames.Last(), assembly.Modules.FirstOrDefault<Module>().ResolveMethod(currentMethod.MDToken.ToInt32()));

        var mainFramesList = mainFrames.ToList();

        for (int i = mainFramesList.Count(); i < 6; i++)
            mainFramesList.Add(mainFrames.Last());
        for (int i = mainFramesList.Count(); i > 6; i--)
            mainFramesList.Remove(mainFramesList.First());

        typeof(StackTrace).GetField("frames", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(this, mainFramesList.ToArray());
        typeof(StackTrace).GetField("m_iMethodsToSkip", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(this, 4);
        typeof(StackTrace).GetField("m_iNumOfFrames", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(this, 2);
    }
}

internal class StringDecrypter
{
    private readonly Assembly assembly;
    private object _decryptField;
    private MethodInfo decryptMethod;

    internal StringDecrypter(Assembly assembly)
    {
        this.assembly = assembly;
    }

    internal void ReplaceStrings(IList<TypeDef> typeDefs)
    {
        foreach (TypeDef typeDef in typeDefs)
        {
            foreach (MethodDef methodDef in typeDef.Methods)
            {
                if (methodDef.HasBody)
                {
                    IList<Instruction> instructions = methodDef.Body.Instructions;

                    for (int i = 0; i < instructions.Count; i++)
                    {
                        Instruction instruction = instructions[i];

                        if (instruction.OpCode == OpCodes.Ldsfld && instruction.Operand.ToString().Contains("<Module>::String") && instructions[i + 1].IsLdcI4() && instructions[i + 2].OpCode == OpCodes.Callvirt && instructions[i + 2].Operand.ToString().Contains("Invoke"))
                        {
                            if (this._decryptField == null)
                            {
                                FieldDef fieldDef = (FieldDef)instruction.Operand;
                                this.InitDecryptor(fieldDef);
                            }
                            int idx = (int)instructions[i + 1].Operand;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = this.GetString(idx);
                            instructions[i + 1].OpCode = OpCodes.Nop;
                            instructions[i + 2].OpCode = OpCodes.Nop;
                        }
                    }
                }
            }
        }
    }

    private void InitDecryptor(FieldDef fieldDef)
    {
        FieldInfo fieldInfo = this.assembly.Modules.FirstOrDefault<Module>().ResolveField(fieldDef.MDToken.ToInt32());
        this._decryptField = fieldInfo.GetValue(null);
        this.decryptMethod = this._decryptField.GetType().GetMethod("Invoke");
    }

    private string GetString(int idx)
    {
        return (string)this.decryptMethod.Invoke(this._decryptField, new object[] { idx });
    }
}

internal static class Memory
{
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    internal unsafe static void Hook(MethodBase from, MethodBase to)
    {
        IntPtr address = Memory.GetAddress(from);
        IntPtr address2 = Memory.GetAddress(to);
        uint flNewProtect;
        Memory.VirtualProtect(address, (IntPtr)5, 64u, out flNewProtect);
        if (IntPtr.Size == 8)
        {
            byte* ptr = (byte*)address.ToPointer();
            *ptr = 73;
            ptr[1] = 187;
            *(long*)(ptr + 2) = address2.ToInt64();
            ptr[10] = 65;
            ptr[11] = byte.MaxValue;
            ptr[12] = 227;
        }
        else if (IntPtr.Size == 4)
        {
            byte* ptr2 = (byte*)address.ToPointer();
            *ptr2 = 233;
            *(long*)(ptr2 + 1) = (long)(address2.ToInt32() - address.ToInt32() - 5);
            ptr2[5] = 195;
        }
        uint num;
        Memory.VirtualProtect(address, (IntPtr)5, flNewProtect, out num);
    }

    public static IntPtr GetAddress(MethodBase methodBase)
    {
        RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
        return methodBase.MethodHandle.GetFunctionPointer();
    }
}

internal class AssemblyWriter
{
    private readonly string assemblyPath;

    internal ModuleDefMD moduleDef;
    internal AssemblyWriter(string assemblyPath)
    {
        this.assemblyPath = assemblyPath;

        AssemblyResolver assemblyResolver = new AssemblyResolver();
        ModuleContext moduleContext = new ModuleContext(assemblyResolver);
        assemblyResolver.EnableTypeDefCache = true;
        assemblyResolver.DefaultModuleContext = moduleContext;
        moduleDef = ModuleDefMD.Load(assemblyPath, moduleContext);
        moduleDef.Context = moduleContext;
        moduleDef.Context.AssemblyResolver.AddToCache(moduleDef);
    }

    internal void WriteMethod(MethodDef methodDef)
    {
        MethodDef executingMethod = Script.currentMethod;

        if (executingMethod == null)
        {
            Console.WriteLine("[!] Failed to write " + methodDef);
            return;
        }
        Script.currentMethod = null;
        executingMethod.FreeMethodBody();
        executingMethod.Body = methodDef.Body;
    }

    internal void Save()
    {
        try
        {
            string text = Path.GetDirectoryName(assemblyPath);

            if (!text.EndsWith("\\"))
            {
                text += "\\";
            }

            string filename = text + Path.GetFileNameWithoutExtension(assemblyPath) + "_Unpacked" + Path.GetExtension(assemblyPath);
            ModuleWriterOptions options = new ModuleWriterOptions(moduleDef);
            options.Logger = DummyLogger.NoThrowInstance;
            moduleDef.Write(filename, options);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[!] Exception :\n" + ex.Message);
        }
    }

}