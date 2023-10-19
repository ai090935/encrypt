#!/usr/bin/python3

import os
import sys
import glob
import platform
import subprocess

is_linux = platform.system() == 'Linux'
is_windows = platform.system() == 'Windows'
is_darwin = platform.system() == 'Darwin'

if is_linux:
	compilers = ['g++', 'clang++']
elif is_darwin or is_windows:
	compilers = ['clang++']
standard = ['-x', 'c++', '-std=c++17']
warning = ['-w']
include = ['-I../../include']
if is_linux or is_darwin:
	optimization =  ['-O3', '-flto']
elif is_windows:
	optimization =  ['-O3', '-flto', '-fuse-ld=lld']
out = ['-o', 'a.exe']
source = glob.glob('../../include/crypto/*.cpp')

def get_sanitizer(file):
	if is_windows:
		return [[]]

	sanitizer = [['-fsanitize=address', '-fsanitize=undefined']]
	if file == 'argon2.cpp':
		sanitizer += [['-fsanitize=thread']]
	return sanitizer


files = glob.glob('./*.cpp')
for compiler in compilers:
	for file in files:
		for sanitizer in get_sanitizer(file):
			command = [compiler] + standard + warning + include + optimization + sanitizer + out + source + [file]
			subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, check=True)
			subprocess.run('./a.exe', stderr=sys.stderr, check=True)

os.remove('a.exe')