#region using

using System;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

#endregion

namespace ILProtectorUnpacker
{
    internal class AssemblyWriter
    {
        private readonly string assemblyPath;

        internal ModuleDefMD moduleDef;

        internal AssemblyWriter(string assemblyPath)
        {
            this.assemblyPath = assemblyPath;

            var assemblyResolver = new AssemblyResolver();
            var moduleContext = new ModuleContext(assemblyResolver);
            assemblyResolver.EnableTypeDefCache = true;
            assemblyResolver.DefaultModuleContext = moduleContext;
            moduleDef = ModuleDefMD.Load(assemblyPath, moduleContext);
            moduleDef.Context = moduleContext;
            moduleDef.Context.AssemblyResolver.AddToCache(moduleDef);
        }

        internal void WriteMethod(MethodDef methodDef)
        {
            var executingMethod = Program.CurrentMethod;

            if (executingMethod == null)
            {
                Console.WriteLine("[!] Failed to write " + methodDef);
                return;
            }

            Program.CurrentMethod = null;
            executingMethod.FreeMethodBody();
            executingMethod.Body = methodDef.Body;
        }

        internal void Save()
        {
            try
            {
                var text = Path.GetDirectoryName(assemblyPath);

                if (!text.EndsWith("\\")) text += "\\";

                var filename = text + Path.GetFileNameWithoutExtension(assemblyPath) + "_Unpacked" +
                               Path.GetExtension(assemblyPath);
                var options = new ModuleWriterOptions(moduleDef);
                options.Logger = DummyLogger.NoThrowInstance;
                moduleDef.Write(filename, options);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Exception :\n" + ex.Message);
            }
        }
    }
}