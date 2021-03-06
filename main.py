import sys
from Registry import Registry
import re



reg = Registry.Registry(sys.argv[1])


def check_reg(rpath, rkey, regex=None):
    #rpath = rpath.lower()
    #rkey = rkey.lower()
    try:
        key = reg.open(rpath)
    except Registry.RegistryKeyNotFoundException:
        #print "Couldn't find Run key. Exiting..."
        return
        #sys.exit(-1)

    
    if rkey == "*":
        for value in [v for v in key.values() \
                           if v.value_type() == Registry.RegSZ or \
                              v.value_type() == Registry.RegExpandSZ]:
            rkname = value.name()
            rkvalue = value.value()
            if regex is not None:
                if re.search(regex, rkvalue):
                    print rpath
                    print "%s: %s" % (rkname, rkvalue)
                    print ""
    else:
        value = key.value(rkey)
        print "%s: %s" % (value.name(),str(value.value()))
        



checks = [ { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunServices', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta'  },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\Run', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunOnceEx', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\batfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\comfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\exe|dllfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\htafile\Shell\Open\Command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\piffile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'SOFTWARE\Microsoft\Code Store Database\Distribution Units', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           {  'path': 'Software\Microsoft\Windows NT\CurrentVersion\Windows', 'key' : 'AppInit_DLLs', 'regex' : '.'  }            
         ]

for check in checks:
    try:
        check_reg( check['path'], check['key'], check['regex'])
    except Registry.RegistryParse.RegistryStructureDoesNotExist:
        pass



