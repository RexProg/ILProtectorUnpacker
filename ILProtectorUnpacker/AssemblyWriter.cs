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
            ((AssemblyResolver)moduleDef.Context.AssemblyResolver).AddToCache(moduleDef);
        }

        internal void WriteMethod(MethodDef oldMethodDef, MethodDef newMethodDef)
        {
            if (oldMethodDef == null)
            {
                Console.WriteLine("[!] Failed to write " + newMethodDef);
                return;
            }
            oldMethodDef.FreeMethodBody();
            oldMethodDef.Body = newMethodDef.Body;
        }

        internal void Save()
        {
            try
            {
                var filename = Path.GetFileNameWithoutExtension(assemblyPath) + "_Unpacked" + Path.GetExtension(assemblyPath);
                var filepath = Path.Combine(Path.GetDirectoryName(assemblyPath), filename);
                var options = new ModuleWriterOptions(moduleDef) {Logger = DummyLogger.NoThrowInstance};
                moduleDef.Write(filepath, options);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Exception :\n" + ex.Message);
            }
        }
    }
}