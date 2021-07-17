#!/usr/bin/env python3
#
# Linux Serial Downloader
# Copyright (C) 2021  ycwn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import argparse
import sys
import struct
import serial


SDP_RESPONSE_V1_LEN = 11
SDP_RESPONSE_V2_LEN = 25

SDP_RESPONSE_ACK = 0x06
SDP_RESPONSE_NAK = 0x07

SDP_COMMAND_ERASE_PGM_ONLY = 0x43    # C
SDP_COMMAND_ERASE_PGM_DATA = 0x41    # A
SDP_COMMAND_WRITE_PGM      = 0x57    # W
SDP_COMMAND_READ_PGM       = 0x56    # V
SDP_COMMAND_WRITE_DATA     = 0x45    # E
SDP_COMMAND_SET_SECURITY   = 0x53    # S
SDP_COMMAND_SET_BAUDRATE   = 0x42    # B
SDP_COMMAND_RUN            = 0x55    # U
SDP_COMMAND_SET_ETIM       = 0x54    # T
SDP_COMMAND_SET_ULOAD      = 0x46    # F


def perror(str):
	sys.stderr.write("lsd: ")
	sys.stderr.write(str)
	sys.stderr.write("\n")
	sys.stderr.flush()
	sys.exit(1)



def pwarn(str):
	sys.stderr.write("lsd: ")
	sys.stderr.write(str)
	sys.stderr.write("\n")
	sys.stderr.flush()



def parse_command_line():

	argp = argparse.ArgumentParser(description="Linux Serial Downloader")
	argp.add_argument('-p',  '--port',       action='store',      type=str, help='Serial port to use (/dev/ttyS0)')
	argp.add_argument('-r',  '--baudrate',   action='store',      type=int, help='Baud rate (9600)')
	argp.add_argument('-e',  '--erase',      action='store_true',           help='Erase device')
	argp.add_argument('-v',  '--verify',     action='store_true',           help='Verify ROM after programming')
	argp.add_argument('-b',  '--boot',       action='store_true',           help='Boot code after programming')
	argp.add_argument('-B',  '--boot-addr',  action='store',      type=int, help='Boot address (0x0000)')
	argp.add_argument('-wp', '--write-pgm',  action='store',      type=str, help='File containing new program ROM')
	argp.add_argument('-wd', '--write-data', action='store',      type=str, help='File containing new data ROM')

	argv = argp.parse_args()

	if not argv.port:
		argv.port = '/dev/ttyS0'

	if not argv.baudrate:
		argv.baudrate = 9600

	if not argv.boot_addr:
		argv.boot_addr = 0x0000

	return argv



def hexfile_parse(path):

	seg = 0
	rom = []

	with open(path, 'r') as hex:
		for n, s in enumerate(hex):

			if s[0] != ":":
				perror("%s:%d: Invalid record, marker missing" % (path, n + 1))

			rec = [ int(s[n+1:n+3], 16) for n in range(0, len(s) - 2, 2) ]

			if rec[0] != len(rec) - 5:
				perror("%s:%d: Partial record, data counter mismatch" % (path, n + 1))

			if rec[-1] != -sum(rec[:-1]) & 0xff:
				perror("%s:%d: Record checksum mismatch" % (path, n + 1))

			if   rec[3] == 0x00: rom.append([ seg + rec[1] * 256 + rec[2] ] + rec[4:4+rec[0]])
			elif rec[3] == 0x01: break
			elif rec[3] == 0x02: seg = rec[4] * 4096     + rec[5] * 16
			elif rec[3] == 0x04: seg = rec[4] * 16777216 + rec[5] * 65536

	return rom



def device_identify(dev):

	dev.write(b'!')
	data = dev.read(SDP_RESPONSE_V1_LEN)

	if len(data) == 0:
		dev.write(b"Z\x00\xA6")
		data = dev.read(SDP_RESPONSE_V2_LEN)

	if len(data) == SDP_RESPONSE_V1_LEN:

		header = struct.unpack("=8s3s", data)

		return {
			'sdp':      1,
			'product':  header[0].decode('utf-8'),
			'version':  header[1].decode('utf-8'),
			'config':   [ 0, 0 ],
			'reserved': [ 0, 0, 0, 0, 0, 0 ],
			'checksum': 0
		}

	elif len(data) == SDP_RESPONSE_V2_LEN:

		header = struct.unpack("=10s4s11B", data)

		return {
			'sdp':      2,
			'product':  header[0].decode('utf-8'),
			'version':  header[1].decode('utf-8'),
			'config':   header[4:6],
			'reserved': header[6:12],
			'checksum': header[12]
		}

	return None



def device_command(dev, cmd, data, rsplen):

	cksum  = -(cmd + len(data) + 1 + sum(data)) & 0xff
	buffer = [ 0x07, 0x0e, len(data) + 1, cmd ] + data + [ cksum ]

	dev.write(struct.pack("=%dB" % len(buffer), *buffer))

	response = dev.read(rsplen + 1)
	response = struct.unpack("=%dB" % len(response), response)

	if rsplen == 0:
		return response[0] == SDP_RESPONSE_ACK

	if len(response) != rsplen + 1:
		return None

	if -sum(response[:-1]) & 0xff != response[-1]:
		return None

	return response[:-1]



def device_erase(dev, data):

	if data:
		pwarn("Erasing program and data ROM")
		device_command(dev, SDP_COMMAND_ERASE_PGM_DATA, [], 0)

	else:
		pwarn("Erasing program ROM")
		device_command(dev, SDP_COMMAND_ERASE_PGM_ONLY, [], 0)



def device_program(dev, cmd, path):

	rom = hexfile_parse(path)

	pwarn("Loaded %d ROM blocks from %s" % (len(rom), path))

	for block in rom:

		pwarn("Writing %d bytes at %#x" % (len(block) - 1, block[0]))

		addr = [
			(block[0] >> 16) & 0xff,
			(block[0] >>  8) & 0xff,
			(block[0] >>  0) & 0xff
		]

		if not device_command(dev, cmd, addr + block[1:], 0):
			perror("Failed!")

	pwarn("Done!")



def device_verify(dev, cmd, path):

	rom = hexfile_parse(path)

	pwarn("Loaded %d ROM blocks from %s" % (len(rom), path))

	for block in rom:

		pwarn("Veryfying %d bytes at %#x" % (len(block) - 1, block[0]))

		page    = (block[0] >> 8) & 0xff
		addr    = (block[0] >> 0) & 0xff
		readout = device_command(dev, cmd, [ page ], 256)

		if not readout:
			perror("Read failed!")

		for n in range(len(block) - 1):

			rom_byte = block[n + 1]
			pgm_byte = readout[addr + n]

			if rom_byte != pgm_byte:
				perror("Verification failed at address %x: W:%x, R:%x" % (page + addr + n, rom_byte, pgm_byte))

	pwarn("Done!")



def device_boot(dev, addr):

	bootaddr = [
		(addr >> 16) & 0xff,
		(addr >>  8) & 0xff,
		(addr >>  0) & 0xff
	]

	if not device_command(dev, SDP_COMMAND_RUN, bootaddr, 0):
		perror("Failed!")

	pwarn("Done!")



argv = parse_command_line()

with serial.Serial(argv.port, argv.baudrate, timeout=1) as dev:

	info = device_identify(dev)

	if not info:
		perror("Failed to detect a compatible device on port %s" % argv.port)

	pwarn("Detected device:")
	pwarn("\tprotocol: %s" % info['sdp'])
	pwarn("\tproduct:  %s" % info['product'])
	pwarn("\tfirmware: %s" % info['version'])

	if info['sdp'] != 2:
		perror("Protocol version %d is not supported" % info['sdp'])


	if argv.erase:
		if argv.write_pgm:
			device_erase(dev, argv.write_data)

		elif argv.write_data:
			perror("Unable to erase data ROM only")


	if argv.write_pgm:

		pwarn("Writing program ROM")
		device_program(dev, SDP_COMMAND_WRITE_PGM, argv.write_pgm)

		if argv.verify:
			pwarn("Verifying program ROM")
			device_verify(dev, SDP_COMMAND_READ_PGM, argv.write_pgm)


	if argv.write_data:
		pwarn("Writing data ROM")
		device_program(dev, SDP_COMMAND_WRITE_DATA, argv.write_data)


	if argv.boot:
		pwarn("Booting")
		device_boot(dev, argv.boot_addr)
