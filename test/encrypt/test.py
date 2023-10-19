#!/usr/bin/python3

import os
import sys
import glob
import platform
import subprocess

is_linux = platform.system() == 'Linux'
is_windows = platform.system() == 'Windows'
is_darwin = platform.system() == 'Darwin'
use_openssl = len(sys.argv) >= 2 and sys.argv[1] == 'use_openssl'

if is_linux:
	compilers = ['g++', 'clang++']
elif is_darwin or is_windows:
	compilers = ['clang++']
standard = ['-x', 'c++', '-std=c++17']
warning = ['-w']
macro = ['-D', 'libencrypt_use_openssl'] if use_openssl else []
include = ['-I../../include']
if is_linux or is_darwin:
	optimization =  ['-O3', '-flto']
elif is_windows:
	optimization =  ['-O3', '-flto', '-fuse-ld=lld']
if is_linux or is_darwin:
	sanitizers = [['-fsanitize=address', '-fsanitize=undefined'], ['-fsanitize=thread']]
elif is_windows:
	sanitizers = [[]]
out = ['-o', 'a.exe']
source = ['../../program/encrypt/src/main.cpp'] + glob.glob('../../include/libencrypt/*.cpp')
if not use_openssl:
	source += glob.glob('../../include/crypto/*.cpp')
if use_openssl:
	opt = sys.argv[2:] if len(sys.argv) >= 3 else ['-lcrypto']
else:
	opt = []

#----------------------------------------------------------------------------------------------------

def test_decrypt():
	args = [
		['-k', 'argon2i,1,274261,2', '-c', 'aes-128-ctr,aes-192-ctr', '-m', 'hmac-sha1,hmac-sha256', '-p', 'pass', '-s', 'key'],
		['-k', 'argon2d,3,499782,4', '-c', 'aes-256-ctr,chacha20', '-m', 'hmac-sha512,poly1305'],
		['-k', 'argon2id,1,2097152,4', '-c', 'chacha20', '-m', 'poly1305'],
	]

	block = b'\0' * 1024
	for i, arg in zip(range(1, 4), args):
		subprocess.run(['./a.exe', '-d', '-i', f'ciphertext{i}', '-o', 'plaintext'] + arg, stderr=sys.stderr, check=True)
		with open('plaintext', "rb") as f:
			if f.read() != block:
				raise RuntimeError("test_decrypt fail")

def test_encrypt():
	args = [
		['-k', 'argon2i,2,909463,3', '-c', 'aes-128-ctr,aes-192-ctr', '-m', 'hmac-sha1,hmac-sha256'],
		['-k', 'argon2d,1,697255,2', '-c', 'aes-256-ctr,chacha20', '-m', 'hmac-sha512,poly1305'],
		['-k', 'argon2id,3,48758,1', '-c', 'chacha20', '-m', 'poly1305'],
	]
	for arg in args:
		subprocess.run(['./a.exe', '-e', '-i', 'zero', '-o', 'ciphertext'] + arg, stderr=sys.stderr, check=True)
		subprocess.run(['./a.exe', '-d', '-i', 'ciphertext', '-o', 'plaintext'] + arg, stderr=sys.stderr, check=True)
		block = b'\0' * 1024 * 1024
		with open('plaintext', "rb") as f:
			for _ in range(1024):
				if f.read(1024 * 1024) != block:
					raise RuntimeError("test_encrypt fail")

def test_mac():
	result = subprocess.run(['./a.exe', '-d', '-k', 'argon2d,1,8,1', '-i', 'ciphertext1', '-o', 'plaintext'], stderr=subprocess.PIPE)
	if (result.returncode == 0) or ('libencrypt::read_mac MAC verify failure' not in result.stderr.decode()):
		raise RuntimeError("test_mac fail")

def test_stdio():
	block = b'\0' * 1024
	result1 = subprocess.run(['./a.exe', '-e', '-k', 'argon2d,1,8,1'], input=block, stdout=subprocess.PIPE, stderr=sys.stderr, check=True)
	result2 = subprocess.run(['./a.exe', '-d', '-k', 'argon2d,1,8,1'], input=result1.stdout, stdout=subprocess.PIPE, stderr=sys.stderr, check=True)
	if result2.stdout != block:
		raise RuntimeError("test_stdio fail")

#----------------------------------------------------------------------------------------------------

block = b'\0' * 1024 * 1024
with open('zero', 'wb') as f:
	for _ in range(1024):
		f.write(block)

for compiler in compilers:
	for sanitizer in sanitizers:
		command = [compiler] + standard + warning + macro + include + optimization + sanitizer + out + source + opt
		subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, check=True)
		test_decrypt()
		test_encrypt()
		test_mac()
		if is_linux or is_darwin:
			test_stdio()

for i in ['a.exe', 'zero', 'plaintext', 'ciphertext']:
	os.remove(i)