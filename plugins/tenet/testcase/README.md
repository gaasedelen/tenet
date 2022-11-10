# Sample Testcases

In these folders are sample traces that have been provided to verify installation and explore basic functionality. 

You can load the provided binary into IDA Pro, and then load its respective `trace.log` via the `File --> Load file --> Tenet trace file...` menu entry.

## Boombox

This is a sample trace of exploitation challenge called `boombox.exe` run with the following pin tracer command:

```
C:\pin\pin.exe -t obj-intel64\pintenet.dll -w boombox.exe -- boombox.exe
```

During the trace, I entered a few commands, before quitting. 

## Solitaire

This is a sample trace of Windows XP solitaire `sol.exe` run with the following pin tracer command:

```
C:\pin\pin.exe -t obj-ia32\pintenet.dll -w sol.exe -- sol.exe
```

During the trace, I moved a few cards, and closed the application.