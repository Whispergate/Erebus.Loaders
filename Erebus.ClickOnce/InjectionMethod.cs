using System;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public interface IInjectionMethod
    {
        bool Inject(byte[] shellcode, int targetPid = 0);
        string Name { get; }
        string Description { get; }
    }

    public enum InjectionType
    {
        SelfInjection,
        RemoteInjection
    }
}
