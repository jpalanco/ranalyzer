

MONGODB_SERVER = 'localhost'
MONGODB_PORT = 27017

UPLOAD_FOLDER = "uploads/"
MAX_CONTENT_LENGTH= 100 * 1024 * 1024

BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = "redis"
CELERY_REDIS_HOST = "localhost"
CELERY_REDIS_PORT = 6379
CELERY_REDIS_DB = 0

STARTUP_CHECKS = [ { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunServices', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta'  },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\Run', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\RunOnceEx', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           # SOFTWARE in root
           { 'path' : 'Microsoft\Windows\CurrentVersion\RunServices', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta'  },
           { 'path' : 'Microsoft\Windows\CurrentVersion\RunServicesOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Windows\CurrentVersion\RunOnce', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Windows\CurrentVersion\RunOnceEx', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },

         ]


OTHER_CHECKS = [ { 'path' : 'Software\CLASSES\batfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\comfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\exe|dllfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\htafile\Shell\Open\Command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\CLASSES\piffile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'SOFTWARE\Microsoft\Code Store Database\Distribution Units', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Software\Microsoft\Windows NT\CurrentVersion\Windows', 'key' : 'AppInit_DLLs', 'regex' : ''  },
           # SOFTWARE in root
           { 'path' : 'CLASSES\batfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'CLASSES\comfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'CLASSES\exe|dllfile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'CLASSES\htafile\Shell\Open\Command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'CLASSES\piffile\shell\open\command', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Code Store Database\Distribution Units', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Windows\CurrentVersion\Explorer\Shell Folders', 'key' : '*', 'regex' : 'exe|dll|bat|pif|com|hta' },
           { 'path' : 'Microsoft\Windows NT\CurrentVersion\Windows', 'key' : 'AppInit_DLLs', 'regex' : ''  } 

         ]         

# FIXME: use regular expressions
WHITELIST = [{'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'Dolby Advanced Audio v2', 'value' : '"C:\Program Files\Dolby Advanced Audio v2\pcee4.exe" -autostart', 'description' : 'Improves PC audio with technologies that maintain volume levels, prevent distortion' },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'Integrated Camera_Monitor', 'value' : '"C:\Program Files\Integrated Camera\monitor.exe"', 'description' : 'Utility for Sunplus webcam' },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'IMSS', 'value' : '"C:\Program Files\Intel\Intel(R) Management Engine Components\IMSS\PIconStartup.exe"', 'description' : 'Intel Management and Security Status' },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'USB3MON', 'value' : '"C:\Program Files\Intel\Intel(R) USB 3.0 eXtensible Host Controller Driver\Application\iusb3mon.exe"', 'description' : 'Intel USB (Version 3.0 Monitor)' },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'TpShocks', 'value' : 'TpShocks.exe', 'description' : 'Lenovo ssd protection' },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'IgfxTray', 'value' : '"C:\Windows\system32\igfxtray.exe"', 'description' : 'Quick access to the control panel via a System Tray icon for graphics based upon the Intel chipsets'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'HotKeysCmds', 'value' : '"C:\Windows\system32\hkcmd.exe"', 'description' : 'Sort cut for graphics based upon the Intel chipsets'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'Persistence', 'value' : '"C:\Windows\system32\igfxpers.exe"', 'description' : 'Associated with the Common User Interface module for Intel graphics cards'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'BLEServicesCtrl', 'value' : 'C:\Program Files\Intel\Bluetooth\BleServicesCtrl.exe', 'description' : 'Related to Intel Corporation Bluetooth LE Services Control Program'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'BTMTrayAgent', 'value' : 'rundll32.exe "C:\Program Files\Intel\Bluetooth\btmshellex.dll",TrayApp', 'description' : 'This file is the tray application installed to support Bluetooth wireless products'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'PWMTRV', 'value' : 'rundll32 "C:\Program Files\ThinkPad\Utilities\PWMTR32V.DLL",PwrMgrBkGndMonitor', 'description' : 'Related to IBM Lenovo ThinkPad Power Manager.'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'SynTPEnh', 'value' : '%ProgramFiles%\Synaptics\SynTP\SynTPEnh.exe', 'description' : 'Synaptics TouchPad Enhancements'},   
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'BCSSync', 'value' : '"C:\Program Files\Microsoft Office\Office14\BCSSync.exe" /DelayServices', 'description' : 'Part of SharePoint Server 2010 which is part of the Microsoft Office suite'},   
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'Windows Mobile Device Center', 'value' : '%windir%\WindowsMobile\wmdc.exe', 'description' : 'mobile device management/synchronization software for Windows7'},
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'McAfeeUpdaterUI', 'value' : '"C:\Program Files\McAfee\Common Framework\udaterui.exe" /StartedFromRunKey', 'description' : 'Updater user interface for McAfee\'s VirusScan Enterprise corporate anti-virus and anti-spyware security tool'  },
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'Communicator', 'value' : '"C:\Program Files\Microsoft Lync\communicator.exe" /fromrunkey', 'description' : 'Microsoft Office Communicator is an integrated communications client that allows information workers to communicate in real time'},      
             {'path' : 'Microsoft\Windows\CurrentVersion\Run', 'key' : 'FveNotify', 'value' : 'C:\Windows\System32\fvenotify.exe', 'description' : 'BitLocker Drive Encryption Notification Utility'},
             {'path' : 'CLASSES\htafile\Shell\Open\Command', 'key' : '(default)', 'value' : 'C:\Windows\System32\mshta.exe "%1" %*', 'description' : 'mshta.exe is a part of Microsoft Windows Operating System which is needed to execute .HTA files'},

         ]