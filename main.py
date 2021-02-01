import socket
import os
import json
import time
import struct


error = [
	'',
	'file not found',
	'access violation',
	'disk full or allocation exceeded',
	'illegal TFTP operation',
	'unknown transfer ID',
	'file already exists',
	'no such user'
]


def get_string(data, offset):
	string = ''
	while True:
		char = data[offset]
		if char != 0:
			string += chr(char)
			offset += 1
		else:
			break
	return (string, offset + 1)


def receive(server_socket, interval=0.001, size=2048):
	while True:
		try:
			return server_socket.recvfrom(size)
		except BlockingIOError:
			time.sleep(interval)
			continue


def parse(data):
	opcode = struct.unpack('!H', data[0:2])[0]
	if opcode == 1:
		index = 2
		filename, index = get_string(data, index)
		mode, index = get_string(data, index)
		return (opcode, filename, mode.lower())
	elif opcode == 2:
		index = 2
		filename, index = get_string(data, index)
		mode, index = get_string(data, index)
		return (opcode, filename, mode.lower())
	elif opcode == 3:
		block = struct.unpack('!H', data[2:4])[0]
		data = data[4:]
		return (opcode, block, data)
	elif opcode == 4:
		block = struct.unpack('!H', data[2:4])[0]
		return (opcode, block)
	elif opcode == 5:
		code = struct.unpack('!H', data[2:4])[0]
		message = get_string(data, 5).decode('ascii')
		return (opcode, code, message)
	else:
		return


def serve_read(root, server_socket, address, filename, mode):
	if os.path.isfile(root + filename):
		print('request from {}:{}'.format(address[0], address[1]))
		print('\toperation : read')
		print('\tfilename  : {}'.format(filename))
		print('\tmode      : {}'.format(mode))
		blocks = list()
		with open(root + filename, 'rb') as file:
			while True:
				data = file.read(512)
				if not data:
					break
				blocks.append(data)
		if len(blocks[-1]) == 512:
			blocks.append(b'')  # <--- 😊
		print('\tblocks    : {}'.format(len(blocks)))
		for block, data in enumerate(blocks):
			block += 1
			# print('\t\t~ sending block {}'.format(block), end=' = ')
			send_data(server_socket, address, block, data, mode)
			request, address = receive(server_socket)
			result = parse(request)
			if result[0] != 4:
				# print('not ok (wrong opcode {})'.format(result[0]))
				send_error(server_socket, address, 4, error[4])
			elif result[1] != block:
				# print('not ok (wrong block {})'.format(result[1]))
				send_error(server_socket, address, 5, error[5])
			else:
				pass
				# print('ok ({}b)'.format(len(data)))
	else:
		send_error(server_socket, address, 1, error[1])


def serve_write(root, server_socket, address, filename, mode):
	if not os.path.isfile(root + filename):
		print('request from {}:{}'.format(address[0], address[1]))
		print('\toperation : write')
		print('\tfilename  : {}'.format(filename))
		print('\tmode      : {}'.format(mode))
		with open(root + filename, 'wb') as file:
			block = 0
			while True:
				send_ack(server_socket, address, block)
				block += 1
				# print('\t\t~ receiving block {}'.format(block), end=' = ')
				request, address = receive(server_socket)
				result = parse(request)
				if result[0] != 3:
					# print('not ok (wrong opcode {})'.format(result[0]))
					send_error(server_socket, address, 4, error[4])
				elif result[1] != block:
					# print('not ok (wrong block {})'.format(result[1]))
					send_error(server_socket, address, 5, error[5])
				else:
					block_len = len(result[2])
					# print('ok ({}b)'.format(block_len))
					if block_len == 512:
						file.write(result[2])
					elif block_len < 512:
						file.write(result[2])
						send_ack(server_socket, address, block)
						break
					else:
						send_ack(server_socket, address, block)
						break
	else:
		send_error(server_socket, address, 6, error[6])


def send_data(server_socket, address, block, data, mode):
	response = struct.pack('!HH', 3, block)
	if mode == 'octet':
		response += data
	elif mode == 'netascii':
		response += data.decode('ascii').encode('ascii')
	else:
		raise Exception(NotImplemented)
	server_socket.sendto(response, address)


def send_ack(server_socket, address, block):
	response = struct.pack('!HH', 4, block)
	server_socket.sendto(response, address)


def send_error(server_socket, address, code, message):
	response = struct.pack('!HH', 5, code)
	response += message.encode('utf-8')
	response += struct.pack('!B'.format(), 0)
	server_socket.sendto(response, address)
	print('error code {}: {}'.format(code, message))


def parse_request(root, server_socket, request, address):
	result = parse(request)
	opcode = result[0]
	if opcode == 1:
		filename = result[1]
		mode = result[2]
		serve_read(root, server_socket, address, filename, mode)
	elif opcode == 2:
		filename = result[1]
		mode = result[2]
		serve_write(root, server_socket, address, filename, mode)
	else:
		send_error(server_socket, address, 4, error[4])


def main():
	ip = '127.0.0.1'
	port = 69
	root = 'resources' + os.sep
	if os.path.isfile('settings.json'):
		print('reading settings file')
		with open('settings.json', 'r') as file:
			settings = json.loads(file.read())
		if 'ip' in settings:
			ip = settings['ip']
		if 'port' in settings:
			port = settings['port']
		if 'root' in settings:
			root = settings['root']
	if len(root):
		if root[-1] != os.sep:
			root += os.sep
	print('\taddress : {}'.format(ip))
	print('\tport    : {}'.format(port))
	print('\troot    : {}'.format(root))
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_socket.setblocking(0)
	server_socket.bind((ip, port))
	while True:
		request, address = receive(server_socket)
		if len(request):
			parse_request(root, server_socket, request, address)


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		pass
