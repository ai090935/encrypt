#!/usr/bin/python3

import sys
import glob
import platform
import subprocess

is_linux = platform.system() == 'Linux'
is_windows = platform.system() == 'Windows'
is_darwin = platform.system() == 'Darwin'
use_openssl = len(sys.argv) >= 2 and sys.argv[1] == 'use_openssl'

if is_linux:
	compiler = ['g++']
elif is_windows or is_darwin:
	compiler = ['clang++']
standard = ['-x', 'c++', '-std=c++17']
warning = ['-pedantic', '-Wall', '-Wextra']
macro = ['-D', 'libencrypt_use_openssl'] if use_openssl else []
include = ['-I../../include']
if is_linux or is_darwin:
	optimization =  ['-O3', '-flto']
elif is_windows:
	optimization =  ['-O3', '-flto', '-fuse-ld=lld']
if is_linux or is_darwin:
	out = ['-o', 'encrypt']
elif is_windows:
	out = ['-o', 'encrypt.exe']
source = ['src/main.cpp'] + glob.glob('../../include/libencrypt/*.cpp')
if not use_openssl:
	source += glob.glob('../../include/crypto/*.cpp')
if use_openssl:
	opt = sys.argv[2:] if len(sys.argv) >= 3 else ['-lcrypto']
else:
	opt = []

linter = ['clang-tidy']
check = ['-checks=-*,clang-analyzer-*,concurrency-*']

# run linter
command = linter + check + source + ['--'] + standard + macro + include + opt
subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, check=True)

# run compiler
command = compiler + standard + warning + macro + include + optimization + out + source + opt
subprocess.run(command, stdout=sys.stdout, stderr=sys.stderr, check=True)