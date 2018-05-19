#region using

using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

#endregion

namespace ILProtectorUnpacker
{
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
            foreach (var typeDef in typeDefs)
            foreach (var methodDef in typeDef.Methods)
                if (methodDef.HasBody)
                {
                    var instructions = methodDef.Body.Instructions;

                    for (var i = 0; i < instructions.Count; i++)
                    {
                        var instruction = instructions[i];

                        if (instruction.OpCode == OpCodes.Ldsfld &&
                            instruction.Operand.ToString().Contains("<Module>::String") &&
                            instructions[i + 1].IsLdcI4() && instructions[i + 2].OpCode == OpCodes.Callvirt &&
                            instructions[i + 2].Operand.ToString().Contains("Invoke"))
                        {
                            if (_decryptField == null)
                            {
                                var fieldDef = (FieldDef) instruction.Operand;
                                InitDecryptor(fieldDef);
                            }

                            var idx = (int) instructions[i + 1].Operand;
                            instructions[i].OpCode = OpCodes.Ldstr;
                            instructions[i].Operand = GetString(idx);
                            instructions[i + 1].OpCode = OpCodes.Nop;
                            instructions[i + 2].OpCode = OpCodes.Nop;
                        }
                    }
                }
        }

        private void InitDecryptor(FieldDef fieldDef)
        {
            var fieldInfo = assembly.Modules.FirstOrDefault().ResolveField(fieldDef.MDToken.ToInt32());
            _decryptField = fieldInfo.GetValue(null);
            decryptMethod = _decryptField.GetType().GetMethod("Invoke");
        }

        private string GetString(int idx)
        {
            return (string) decryptMethod.Invoke(_decryptField, new object[] {idx});
        }
    }
}