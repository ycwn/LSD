# LSD - Linux Serial Downloader

This is a programmer for devices using Analog Devices' Serial Download Protocol (version 2).

## Usage:
```
	lsd.py [-p port] [-r baudrate] [-e] [-v] [-b] [-B addr] [-wp path] [-wd path]
```

 Short | Long option    | Argument    | Description                        |  Default
-------|----------------|-------------|------------------------------------|--------------
  -p   |  --port        |  dev-path   |  Serial port to use                |  /dev/ttyS0
  -r   |  --baudrate    |  int        |  Baud rate                         |  9600
  -e   |  --erase       |             |  Erase device                      |  No
  -v   |  --verify      |             |  Verify ROM after programming      |  No
  -b   |  --boot        |             |  Boot code after programming       |  No
  -B   |  --boot-addr   |  int        |  Boot address                      |  0x0000
  -wp  |  --write-pgm   |  file-path  |  File containing new program ROM   | 
  -wd  |  --write-data  |  file-path  |  File containing new data ROM      |



The erase option is used in conjuction with the corresponding write option.

For example, this will erase only the program ROM:
```
	lsd.py -e -wp prog.hex
```
while this will erase both program and data ROMs:
```
	lsd.py -e -wp prog.hex -wd data.hex
```

Verification can only be done for the program ROM.

This has been tested with the Microconverter ADuC847 evaluation board.

# Further information
For further information on how the serial download protocol operates,

see Analog Devices' application note AN-1074, 'Understanding the Serial Download Protocol':

https://www.analog.com/media/en/evaluation-boards-kits/evaluation-software/AN-1074.pdf

