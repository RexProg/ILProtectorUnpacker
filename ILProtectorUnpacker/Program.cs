#region using

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using MonoMod.Utils;

#endregion

namespace ILProtectorUnpacker
{
    internal class Program
    {
        public static int IgnoreIndex = -1;
        public static AssemblyWriter AssemblyWriter;
        public static Assembly Assembly;
        public static MethodDef CurrentMethod;
        public static MethodBase CurrentMethodBase;
        public static StackFrame[] MainFrames;
        public static List<TypeDef> JunkType = new List<TypeDef>();

        private static int _totalPackedMethods;
        private static int _totalUnpackedMethods;

        private static void Main(string[] args)
        {
            try
            {
                if (args.Length == 2 && args[0] == "-i") IgnoreIndex = Convert.ToInt32(args[1]);
                Console.BackgroundColor = ConsoleColor.White;
                Console.ForegroundColor = ConsoleColor.Black;
                Console.WriteLine("*********************************");
                Console.WriteLine("***                           ***");
                Console.WriteLine("***    ILProtector Unpacker   ***");
                Console.WriteLine("***   V2.0.21.2 - V2.0.22.14  ***");
                Console.WriteLine("***     Coded By RexProg      ***");
                Console.WriteLine("***     Updated By krysty     ***");
                Console.WriteLine("***                           ***");
                Console.WriteLine("*********************************");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("[?] Enter Your Program Path : ");
                Console.ForegroundColor = ConsoleColor.Red;

                var path = Console.ReadLine();

                if (string.IsNullOrEmpty(path))
                {
                    if (args.Length == 1)
                    {
                        path = args[0];
                    }
                    else
                    {
                        return;
                    }
                }

                if (path != null && path.StartsWith("\"") && path[path.Length - 1] == '"')
                    path = path.Substring(1, path.Length - 2);

                if (!File.Exists(path))
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("[!] File not found");
                    Console.WriteLine("[!] Press key to exit...");
                    Console.Read();
                    return;
                }

                if (!HasWritePermission(path))
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.WriteLine("[!] Can't write to " + Path.GetDirectoryName(path));
                    Console.WriteLine("[!] Press key to exit...");
                    Console.Read();
                    return;
                }

                Console.ForegroundColor = ConsoleColor.DarkRed;

                AssemblyWriter = new AssemblyWriter(path);
                Assembly = Assembly.LoadFrom(path ?? throw new Exception("path is null"));
                Console.WriteLine("[+] Wait...");

                HookSystemRuntimeTypeGetMethodBase();

                MainFrames = new StackTrace().GetFrames();

                //Memory.Hook(
                //    typeof(StackTrace).GetMethod("GetFrame", BindingFlags.Instance | BindingFlags.Public),
                //    typeof(Program).GetMethod(nameof(Hook), BindingFlags.Instance | BindingFlags.Public)
                //);

                //Memory.Hook(
                //    typeof(StackFrame).GetMethod("SetMethodBase", BindingFlags.Instance | BindingFlags.NonPublic),
                //    typeof(Program).GetMethod(nameof(Hook2), BindingFlags.Instance | BindingFlags.Public)
                //);

                //Memory.Hook(
                //    typeof(StackTrace).GetMethod("CaptureStackTrace", BindingFlags.Instance | BindingFlags.NonPublic),
                //    typeof(Program).GetMethod(nameof(Hook3), BindingFlags.Instance | BindingFlags.Public)
                //);

                Memory.Hook(
                    typeof(StackTrace).Module.GetType("System.Diagnostics.StackFrameHelper")
                        .GetMethod("GetMethodBase", BindingFlags.Instance | BindingFlags.Public),
                    typeof(Program).GetMethod(nameof(Hook4), BindingFlags.Instance | BindingFlags.Public)
                );

                var types = AssemblyWriter.moduleDef.GetTypes();
                var list = types as IList<TypeDef> ?? types.ToList();

                var globalType = AssemblyWriter.moduleDef.GlobalType;

                var fieldMdToken = globalType.Fields
                    .Where(fieldDef => fieldDef.Name == "Invoke")
                    .Select(fieldDef => fieldDef.MDToken.ToInt32())
                    .DefaultIfEmpty(0)
                    .FirstOrDefault();

                if (fieldMdToken == 0)
                    Console.WriteLine("[!] Couldn't find Invoke");

                var fieldValue = Assembly.Modules.FirstOrDefault()?.ResolveField(fieldMdToken).GetValue(null);

                var method = fieldValue?.GetType().GetMethod("Invoke");

                if (method == null)
                    Console.WriteLine("[!] Couldn't find InvokeMethod");

                InvokeDelegates(list, method, fieldValue);

                new StringDecrypter(Assembly).ReplaceStrings(list);

                foreach (var typeDef in JunkType)
                {
                    typeDef.DeclaringType.NestedTypes.Remove(typeDef);
                }

                if (_totalUnpackedMethods == _totalPackedMethods)
                {
                    CleanAssembly();
                }

                AssemblyWriter.Save();
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine($"[!] Total packed methods:   {_totalPackedMethods}");
                Console.WriteLine($"[!] Total unpacked methods: {_totalUnpackedMethods}");
                Console.WriteLine("[!] Program Unpacked");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Exception :\n" + ex.StackTrace);
            }

            Console.WriteLine("[!] Press key to exit...");
            Console.Read();
        }

        private static void InvokeDelegates(IList<TypeDef> typeDefs, MethodInfo invokeMethod, object invokeField)
        {
            var methodDefs = typeDefs.SelectMany(x => x.Methods).Where(x =>
                x.Module.Name == Assembly.ManifestModule.ScopeName && x.HasBody && 
                x.Body.Instructions.Count > 2 &&
                x.Body.Instructions[0].OpCode == OpCodes.Ldsfld &&
                x.Body.Instructions[0].Operand.ToString().Contains("Invoke") && 
                x.Body.Instructions[1].IsLdcI4());

            foreach (var methodDef in methodDefs)
            {
                _totalPackedMethods++;

                CurrentMethod = methodDef;
                CurrentMethodBase = Assembly.ManifestModule.ResolveMethod(methodDef.MDToken.ToInt32());

                var mdToken = ((IType) methodDef.Body.Instructions[3].Operand).MDToken.ToInt32();
                JunkType.Add(methodDef.DeclaringType.NestedTypes.FirstOrDefault(net => net.MDToken.ToInt32() == mdToken));
                var index = methodDef.Body.Instructions[1].GetLdcI4Value();
                if (index == IgnoreIndex) continue;

                var method = invokeMethod.Invoke(invokeField, new object[] {index});

                try
                {
                    var dynamicMethodBodyReader = new DynamicMethodBodyReader(AssemblyWriter.moduleDef, method);
                    dynamicMethodBodyReader.Read();
                    var unpackedMethod = dynamicMethodBodyReader.GetMethod();
                    AssemblyWriter.WriteMethod(methodDef, unpackedMethod);
                    _totalUnpackedMethods++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error in Read(): " + ex.Message + "\nMethod : " + method);
                }
                finally
                {
                    CurrentMethod = null;
                }
            }
        }

        private static void CleanAssembly()
        {
            var globalType = AssemblyWriter.moduleDef.GlobalType;

            IEnumerable<MethodDef> CollectMethodDefsToRemove(TypeDef gTypeDef, MethodDef mDef)
            {
                var methodDefs = new HashSet<MethodDef>();
                if (mDef.HasBody)
                {
                    foreach (var instr in mDef.Body.Instructions
                        .Where(x => x.OpCode == OpCodes.Call)
                        .Where(x => x.Operand is MethodDef)
                        .Where(x => ((MethodDef)x.Operand).FullName.Contains(globalType.Name)))
                    {
                        methodDefs.Add(instr.Operand as MethodDef);
                        foreach (var mdef in CollectMethodDefsToRemove(globalType, instr.Operand as MethodDef))
                        {
                            methodDefs.Add(mdef);
                        }
                    }
                }
                return methodDefs;
            }

            var methodDef = globalType.FindStaticConstructor();

            var methodDefsToRemove = new List<MethodDef>();

            if (methodDef.HasBody)
            {
                var startIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(
                                     inst => inst.OpCode == OpCodes.Call && ((IMethod)inst.Operand).Name == "GetIUnknownForObject")) - 2;

                var endIndex = methodDef.Body.Instructions.IndexOf(methodDef.Body.Instructions.FirstOrDefault(
                                   inst => inst.OpCode == OpCodes.Call && ((IMethod)inst.Operand).Name == "Release")) + 2;

                methodDef.Body.ExceptionHandlers.Remove(methodDef.Body.ExceptionHandlers.FirstOrDefault(
                    exh => exh.HandlerEnd == methodDef.Body.Instructions[endIndex + 1]));

                methodDefsToRemove.AddRange(CollectMethodDefsToRemove(globalType, methodDef));

                for (var i = startIndex; i <= endIndex; i++)
                {
                    methodDef.Body.Instructions.Remove(methodDef.Body.Instructions[startIndex]);
                }
            }

            foreach (var def in globalType.Methods.Where(met => met.HasImplMap)
                .Where(met => new[] { "Protect32.dll", "Protect64.dll" }
                    .Any(x => x == met.ImplMap?.Module.Name.ToString())).ToList())
                globalType.Remove(def);

            var dlls = globalType.Methods.Where(x => x.HasBody && x.Body.HasInstructions)
                .SelectMany(x => x.Body.Instructions)
                .Where(x => x.OpCode == OpCodes.Ldstr && x.Operand is string)
                .Select(x => x.Operand as string)
                .Where(x => !string.IsNullOrEmpty(x))
                .Where(x => x.StartsWith("Protect") && x.EndsWith(".dll"))
                .Distinct()
                .ToArray();

            if (dlls.Any())
            {
                Console.WriteLine(string.Join(", ", dlls));

                var resourcesToRemove = AssemblyWriter.moduleDef.Resources.Where(x => dlls.Any(d => d == x.Name)).ToList();
                resourcesToRemove.ForEach(res => AssemblyWriter.moduleDef.Resources.Remove(res));
            }

            methodDefsToRemove.ForEach(mdef => globalType.Methods.Remove(mdef));

            var fieldDefsToRemove = globalType.Fields.Where(fld => fld.Name == "Invoke" || fld.Name == "String").ToList();

            foreach (var field in fieldDefsToRemove)
            {
                AssemblyWriter.moduleDef.Types.Remove(field.FieldType.ToTypeDefOrRef().ResolveTypeDef());
                globalType.Fields.Remove(field);
            }
        }

        public static bool HasWritePermission(string filePath)
        {
            try
            {
                var tempFilePath = Path.Combine(Path.GetDirectoryName(filePath), "temp.txt");
                File.Create(tempFilePath).Close();
                File.Delete(tempFilePath);
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            return true;
        }

        public StackFrame Hook(int num)
        {
            var frames = new StackTrace().GetFrames();

            if (frames == null) return null;
            for (var i = 0; i < frames.Length; i++)
            {
                var method = frames[i].GetMethod();

                if (num == 0 && method.ToString().StartsWith("System.Delegate (")) return frames[i];
                if (num == 1 && method.ToString().StartsWith("System.Delegate ("))
                {
                    var value = Assembly.Modules.FirstOrDefault()?.ResolveMethod(CurrentMethod.MDToken.ToInt32());
                    typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic)
                        ?.SetValue(frames[i + 1], value);
                    return frames[i + 1];
                }
            }

            return null;
        }

        public void Hook2(MethodBase mb)
        {
            typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.SetValue(this,
                    mb.Name == "InvokeMethod"
                        ? Assembly.Modules.FirstOrDefault()?.ResolveMethod(CurrentMethod.MDToken.ToInt32())
                        : mb);
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
            typeof(StackFrame).GetField("method", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.SetValue(
                    MainFrames.Last(),
                    Assembly.Modules.FirstOrDefault()?.ResolveMethod(CurrentMethod.MDToken.ToInt32()));

            var mainFramesList = MainFrames.ToList();

            for (var i = mainFramesList.Count; i < 6; i++)
                mainFramesList.Add(MainFrames.Last());
            for (var i = mainFramesList.Count; i > 6; i--)
                mainFramesList.Remove(mainFramesList.First());

            typeof(StackTrace).GetField("frames", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.SetValue(this, mainFramesList.ToArray());
            typeof(StackTrace).GetField("m_iMethodsToSkip", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.SetValue(this, 4);
            typeof(StackTrace).GetField("m_iNumOfFrames", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.SetValue(this, 2);
        }

        public MethodBase Hook4(int i)
        {
            var rgMethodHandle = (IntPtr[]) typeof(StackTrace).Module
                .GetType("System.Diagnostics.StackFrameHelper")
                .GetField("rgMethodHandle", BindingFlags.Instance | BindingFlags.NonPublic)
                ?.GetValue(this);

            var methodHandleValue = rgMethodHandle?[i];

            var runtimeMethodInfoStub =
                typeof(StackTrace).Module.GetType("System.RuntimeMethodInfoStub").GetConstructors()[1]
                    .Invoke(new object[] {methodHandleValue, this});

            var typicalMethodDefinition = typeof(StackTrace).Module.GetType("System.RuntimeMethodHandle")
                .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Where(m => m.Name == "GetTypicalMethodDefinition" && m.GetParameters().Length == 1).ToArray()[0]
                .Invoke(null, new[] {runtimeMethodInfoStub});

            var result = (MethodBase) typeof(StackTrace).Module.GetType("System.RuntimeType")
                .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .Where(m => m.Name == "GetMethodBase" && m.GetParameters().Length == 1).ToArray()[0]
                .Invoke(null, new[] {typicalMethodDefinition});

            if (result.Name == "InvokeMethod")
                result = Assembly.Modules.FirstOrDefault()?.ResolveMethod(CurrentMethod.MDToken.ToInt32());
            return result;
        }

        public static void Hook5(ref MethodBase methodBase)
        {
            if (methodBase.Name == "InvokeMethod" && methodBase.DeclaringType == typeof(RuntimeMethodHandle))
            {
                methodBase = CurrentMethodBase;
            }
        }

        private static void HookSystemRuntimeTypeGetMethodBase()
        {
            var systemRuntimeTypeType = typeof(Type).Assembly.GetType("System.RuntimeType");

            var getMethodBase1 = systemRuntimeTypeType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
                .Where(m => m.Name == "GetMethodBase")
                .Where(m => m.GetParameters().Length == 2)
                .FirstOrDefault(m =>
                    m.GetParameters().First().ParameterType == systemRuntimeTypeType &&
                    m.GetParameters().Last().ParameterType.Name == "IRuntimeMethodInfo");

            var getMethodBase2 = systemRuntimeTypeType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
                .FirstOrDefault(m => m.Name == "GetMethodBase" && m.GetParameters().Length == 1);

            var myMethod = typeof(Program).GetMethod(nameof(Hook5), BindingFlags.Static | BindingFlags.Public);

            var replacementMethod = new DynamicMethodDefinition(
                getMethodBase2.Name,
                getMethodBase2.ReturnType,
                getMethodBase2.GetParameters().Select(x => x.ParameterType).ToArray()
            )
            {
                OwnerType = getMethodBase1.DeclaringType
            };

            var iLGenerator = replacementMethod.GetILGenerator();

            iLGenerator.DeclareLocal(typeof(MethodBase), false);

            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ldnull);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Stloc_0);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ldnull);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ldarg_0);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Call, getMethodBase1);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Stloc_0);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ldloca, 0);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Call, myMethod);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ldloc_0);
            iLGenerator.Emit(System.Reflection.Emit.OpCodes.Ret);

            var replacementMethodInfo = replacementMethod.Generate();

            Memory.SimpleHook(getMethodBase2, replacementMethodInfo);
        }
    }
}