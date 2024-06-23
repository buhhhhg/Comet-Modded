global Injected  # inserted
global Injecting  # inserted

import os, sys
import subprocess

def install_package(name: str):
	try:
		package = __import__(name)
	except ModuleNotFoundError:
		print(f"⚠ You dont have {name} installed")
		print("⚠ I'll just do it for you since your probably lazy")
		print()
		subprocess.run(['pip','install',name])
		print(f"\n✔{name} installed, Restart Comet")
		sys.exit(0)

	return package

print("Comet BETA - Modded by k5utils")
print("Anti-debugger has been removed")
print()

tk = install_package('tkinter')
pymem = install_package('pymem')
ctypes = install_package('ctypes')
psutil = install_package('psutil')

from tkinter import filedialog, messagebox
from re import compile as comp
from re import escape
import random
import string
from time import sleep
import json
# from ctypes import windll
# from ctypes import c_int
# from ctypes import c_uint
# from ctypes import c_ulong
# from ctypes import POINTER
# from ctypes import byref
# un-comment if shit doesnt work

LightingScript = '496E6A656374????????????????????06'
RobloxPlayer = ['RobloxPlayerBeta.exe', 'Windows10Universal.exe', 'RobloxCrashHandler.exe']
SpoofName = False
target = False
Injecting = False
Injected = False
NameOffset = 72
ChildrenOffset = 80
ParentOffset = 96
DataModelMethods = ['RenderView', 'GuiRoot']

def GetNameAddress(Instance: int) -> int:
	try:
		ExpectedAddress = InjectorClass.DRP(Instance + NameOffset, True)
		return ExpectedAddress
	except TypeError as e:
		exit()

def GetName(Instance: int) -> str:
	ExpectedAddress = GetNameAddress(Instance)
	return ReadRobloxString(ExpectedAddress)

def GetChildren(Instance: int) -> str:
	ChildrenInstance = []
	InstanceAddress = Instance
	if not InstanceAddress:
		return False
	ChildrenStart = InjectorClass.DRP(InstanceAddress + ChildrenOffset, True)
	if ChildrenStart == 0:
		return []
	ChildrenEnd = InjectorClass.DRP(ChildrenStart + 8, True)
	OffsetAddressPerChild = 16
	CurrentChildAddress = InjectorClass.DRP(ChildrenStart, True)
	try:
		for i in range(0, 9000):
			if i == 8999:
				raise ValueError('[X]: 208')
			if CurrentChildAddress == ChildrenEnd:
				pass  # postinserted
			else:
				return ChildrenInstance
			ChildrenInstance.append(InjectorClass.Pymem.read_longlong(CurrentChildAddress))
			CurrentChildAddress += OffsetAddressPerChild
		else:  # inserted
			return ChildrenInstance
	except ValueError as e:
		exit()

def GetParent(Instance: int) -> int:
	return InjectorClass.DRP(Instance + ParentOffset, True)

def FindFirstChild(Instance: int, ChildName: str) -> int:
	ChildrenOfInstance = GetChildren(Instance)
	for i in ChildrenOfInstance:
		if GetName(i) == ChildName:
			return i
	else:  # inserted
		return

def FindFirstChildOfClass(Instance: int, ClassName: str) -> int:
	ChildrenOfInstance = GetChildren(Instance)
	for i in ChildrenOfInstance:
		if GetClassName(i) == ClassName:
			return i
	else:  # inserted
		return

def GetDescendants(Instance: int) -> list:
	descendants = []

	def _get_descendants_recursive(current_instance: int):
		children = GetChildren(current_instance)
		descendants.extend(children)
		for child in children:
			_get_descendants_recursive(child)
	_get_descendants_recursive(Instance)
	return descendants

class toInstance:
	def __init__(self, address: int=0):
		self.Address = address
		self.Self = address
		self.Name = GetName(address)
		self.ClassName = GetClassName(address)
		self.Parent = GetParent(address)

	def getChildren(self):
		return GetChildren(self.Address)

	def findFirstChild(self, ChildName):
		return FindFirstChild(self.Address, ChildName)

	def findFirstClass(self, ChildClass):
		return FindFirstChildOfClass(self.Address, ChildClass)

	def setParent(self, Parent):
		setParent(self.Address, Parent)

	def GetChildren(self):
		return GetChildren(self.Address)

	def GetDescendants(self):
		return GetDescendants(self.Address)

	def FindFirstChild(self, ChildName):
		return FindFirstChild(self.Address, ChildName)

	def FindFirstClass(self, ChildClass):
		return FindFirstChildOfClass(self.Address, ChildClass)

	def SetParent(self, Parent):
		setParent(self.Address, Parent, ParentOffset, ChildrenOffset)

class InjectorClass:
	def __init__(self, program_name):
		self.program_name = program_name

	def SimpleGetProcesses(self):
		return [proc.name() for proc in psutil.process_iter(['name'])]

	def SetParent(self, Instance, Parent, parentOffset):
		InjectorClass.Pymem.write_longlong(Instance + parentOffset, Parent)

	def __init__(self, ProgramName=None):
		self.ProgramName = ProgramName
		self.Pymem = pymem.Pymem()
		self.Addresses = {}
		self.Handle = None
		self.is64bit = True
		self.ProcessID = None
		self.PID = self.ProcessID
		if type(ProgramName) == str:
			self.Pymem = pymem.Pymem(ProgramName)
			self.Handle = self.Pymem.process_handle
			self.is64bit = pymem.process.is_64_bit(self.Handle)
			self.ProcessID = self.Pymem.process_id
			self.PID = self.ProcessID
		else:  # inserted
			if type(ProgramName) == int:
				self.Pymem.open_process_from_id(ProgramName)
				self.Handle = self.Pymem.process_handle
				self.is64bit = pymem.process.is_64_bit(self.Handle)
				self.ProcessID = self.Pymem.process_id
				self.PID = self.ProcessID

	def h2d(self, hz: str, bit: int=16) -> int:
		if type(hz) == int:
			return hz
		return int(hz, bit)

	def d2h(self, dc: int, UseAuto=None) -> str:
		if type(dc) == str:
			return dc
		if UseAuto:
			if UseAuto == 32:
				dc = hex(dc & 4294967295).replace('0x', '')
			else:  # inserted
				dc = hex(dc & 18446744073709551615).replace('0x', '')
		else:  # inserted
			if abs(dc) > 4294967295:
				dc = hex(dc & 18446744073709551615).replace('0x', '')
			else:  # inserted
				dc = hex(dc & 4294967295).replace('0x', '')
		while len(dc) > 8 and len(dc) < 16:
			dc = '0' + dc
		while len(dc) < 8 and len(dc) < 8:
			dc = '0' + dc
		return dc

	def PLAT(self, aob: str):
		if type(aob) == bytes:
			return aob
		trueB = bytearray(b'')
		aob = aob.replace(' ', '')
		PLATlist = []
		for i in range(0, len(aob), 2):
			PLATlist.append(aob[i:i + 2])
		for i in PLATlist:
			if '?' in i:
				trueB.extend(b'.')
			if '?' not in i:
				trueB.extend(escape(bytes.fromhex(i)))
		return bytes(trueB)

	def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
		try:
			InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(2035711, False, InjectorClass.Pymem.process_id)
			PAGE_EXECUTE_READWRITE = 64
			ntdll = ctypes.windll.ntdll
			NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
			NtProtectVirtualMemory.restype = ctypes.c_long
			base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
			old_protect = ctypes.c_ulong()
			size = ctypes.c_size_t(4096)
			NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
			base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
			NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), old_protect, ctypes.byref(ctypes.c_ulong()))
			return pymem.pattern.pattern_scan_all(self.Pymem.process_handle, self.PLAT(AOB_HexArray), return_multiple=xreturn_multiple)
		except Exception as e:
			try:
				InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(2035711, False, InjectorClass.Pymem.process_id)
				PAGE_EXECUTE_READWRITE = 64
				ntdll = ctypes.windll.ntdll
				NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
				NtProtectVirtualMemory.restype = ctypes.c_long
				base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
				old_protect = ctypes.c_ulong()
				size = ctypes.c_size_t(4096)
				NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
				base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
				NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), old_protect, ctypes.byref(ctypes.c_ulong()))
				return pymem.pattern.pattern_scan_all(self.Pymem.process_handle, self.PLAT(AOB_HexArray), return_multiple=xreturn_multiple)
			except WindowsError as we:
				if we.winerror == 5:
					InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(2035711, False, InjectorClass.Pymem.process_id)
				PAGE_EXECUTE_READWRITE = 64
				ntdll = ctypes.windll.ntdll
				NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
				NtProtectVirtualMemory.restype = ctypes.c_long
				base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
				old_protect = ctypes.c_ulong()
				size = ctypes.c_size_t(4096)
				NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
				base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
				NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), old_protect, ctypes.byref(ctypes.c_ulong()))
				return pymem.pattern.pattern_scan_all(self.Pymem.process_handle, self.PLAT(AOB_HexArray), return_multiple=xreturn_multiple)
			except Exception as e:
				print("Something bad happen'd, now we're going to close road bocks")
				print(f"Error: {str(e)}")
				for pid in (process.pid for process in psutil.process_iter() if process.name()in RobloxPlayer):
					os.kill(pid)
					print(f"🚑 Killed {pid}")
				print()
				raise e

	def gethexc(self, hex: str):
		hex = hex.replace(' ', '')
		hxlist = []
		for i in range(0, len(hex), 2):
			hxlist.append(hex[i:i + 2])
		return len(hxlist)

	def hex2le(self, hex: str):
		lehex = hex.replace(' ', '')
		lelist = []
		if len(lehex) > 8:
			while len(lehex) < 16:
				lehex = '0' + lehex
			for i in range(0, len(lehex), 2):
				lelist.append(lehex[i:i + 2])
			lelist.reverse()
			return ''.join(lelist)
		else:  # inserted
			while len(lehex) < 9 and len(lehex) < 8:
				lehex = '0' + lehex
				for i in range(0, len(lehex), 2):
					lelist.append(lehex[i:i + 2])
				lelist.reverse()
				return ''.join(lelist)

	def calcjmpop(self, des, cur):
		jmpopc = self.h2d(des) - self.h2d(cur) - 5
		jmpopc = hex(jmpopc & 4294967295).replace('0x', '')
		if len(jmpopc) % 2!= 0:
			jmpopc = '0' + str(jmpopc)
		return jmpopc

	def isProgramGameActive(self):
		try:
			self.Pymem.read_char(self.Pymem.base_address)
			return True
		except:
			return False

	def DRP(self, Address: int, is64Bit: bool=None) -> int:
		Address = Address
		if type(Address) == str:
			Address = self.h2d(Address)
		if is64Bit:
			return int.from_bytes(self.Pymem.read_bytes(Address, 8), 'little')
		if self.is64bit:
			return int.from_bytes(self.Pymem.read_bytes(Address, 8), 'little')
		return int.from_bytes(self.Pymem.read_bytes(Address, 4), 'little')

	def isValidPointer(self, Address: int, is64Bit: bool=None) -> bool:
		try:
			if type(Address) == str:
				Address = self.h2d(Address)
			self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
			return True
		except:
			return False

	def GetModules(self) -> list:
		return list(self.Pymem.list_modules())

	def getAddressFromName(self, Address: str) -> int:
		if type(Address) == int:
			return Address
		AddressBase = 0
		AddressOffset = 0
		for i in self.GetModules():
			if i.name in Address:
				AddressBase = i.lpBaseOfDll
				AddressOffset = self.h2d(Address.replace(i.name + '+', ''))
				AddressNamed = AddressBase + AddressOffset
				return AddressNamed
			exit()
		else:  # inserted
			return Address

	def getNameFromAddress(self, Address: int) -> str:
		memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle, Address)
		BaseAddress = memoryInfo.BaseAddress
		NameOfDLL = ''
		AddressOffset = 0
		for i in self.GetModules():
			if i.lpBaseOfDll == BaseAddress:
				NameOfDLL = i.name
				AddressOffset = Address - BaseAddress
				break
		if NameOfDLL == '':
			return Address
		NameOfAddress = NameOfDLL + '+' + self.d2h(AddressOffset)
		return NameOfAddress

	def getRawProcesses(self):
		toreturn = []
		for i in pymem.process.list_processes():
			toreturn.append([i.cntThreads, i.cntUsage, i.dwFlags, i.dwSize, i.pcPriClassBase, i.szExeFile, i.th32DefaultHeapID, i.th32ModuleID, i.th32ParentProcessID, i.th32ProcessID])
		return toreturn

	def SimpleGetProcesses(self):
		toreturn = []
		for i in self.getRawProcesses():
			toreturn.append({'Name': i[5].decode(), 'Threads': i[0], 'ProcessId': i[9]})
		return toreturn

	def YieldForProgram(self, programName, AutoOpen: bool=False, Limit=1):
		Count = 0
		while True:
			if Count >= Limit:
				return False
			ProcessesList = self.SimpleGetProcesses()
			for i in ProcessesList:
				if i['Name'] == programName:
					if AutoOpen:
						self.Pymem.open_process_from_id(i['ProcessId'])
						self.ProgramName = programName
						self.Handle = self.Pymem.process_handle
						self.is64bit = pymem.process.is_64_bit(self.Handle)
						self.ProcessID = self.Pymem.process_id
						self.PID = self.ProcessID
					return True
			else:  # inserted
				sleep(1)
				Count += 1

	def ReadPointer(self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool=None) -> int:
		x = self.DRP(BaseAddress, is64Bit)
		y = Offsets_L2R
		z = x
		if y == None or len(y) == 0:
			return z
		count = 0
		for i in y:
			try:
				print(self.d2h(x + i))
				print(self.d2h(i))
				z = self.DRP(z + i, is64Bit)
				count += 1
				print(self.d2h(z))
			except:
				print('[X]: 208')
				exit()
			else:  # inserted
				return z
		else:  # inserted
			return z

	def GetMemoryInfo(self, Address: int, Handle: int=None):
		if Handle:
			return pymem.memory.virtual_query(Handle, Address)
		return pymem.memory.virtual_query(self.Handle, Address)

	def MemoryInfoToDictionary(self, MemoryInfo):
		return {'BaseAddress': MemoryInfo.BaseAddress, 'AllocationBase': MemoryInfo.AllocationBase, 'AllocationProtect': MemoryInfo.AllocationProtect, 'RegionSize': MemoryInfo.RegionSize, 'State': MemoryInfo.State, 'Protect': MemoryInfo.Protect, 'Type': MemoryInfo.Type}

	def SetProtection(self, Address: int, ProtectionType=64, Size: int=4, OldProtect=ctypes.c_ulong(0)):
		pymem.ressources.kernel32.VirtualProtectEx(self.Pymem.process_handle, Address, Size, ProtectionType, ctypes.byref(OldProtect))
		return OldProtect

	def ChangeProtection(self, Address: int, ProtectionType=64, Size: int=4, OldProtect=ctypes.c_ulong(0)):
		return self.SetProtection(Address, ProtectionType, Size, OldProtect)

	def GetProtection(self, Address: int):
		return self.GetMemoryInfo(Address).Protect

	def KnowProtection(self, Protection):
		if Protection == 16:
			return 'PAGE_EXECUTE'
		if Protection == 32:
			return 'PAGE_EXECUTE_READ'
		if Protection == 64:
			return 'PAGE_EXECUTE_READWRITE'
		if Protection == 128:
			return 'PAGE_EXECUTE_WRITECOPY'
		if Protection == 1:
			return 'PAGE_NOACCESS'
		if Protection == 2:
			return 'PAGE_READONLY'
		if Protection == 4:
			return 'PAGE_READWRITE'
		if Protection == 8:
			return 'PAGE_WRITECOPY'
		if Protection == 256:
			return 'PAGE_GUARD'
		if Protection == 512:
			return 'PAGE_NOCACHE'
		if Protection == 1024:
			return 'PAGE_WRITECOMBINE'
		if Protection in ['PAGE_EXECUTE', 'execute', 'e']:
			return 16
		if Protection in ['PAGE_EXECUTE_READ', 'execute read', 'read execute', 'execute_read', 'read_execute', 'er', 're']:
			return 32
		if Protection in ['PAGE_EXECUTE_READWRITE', 'execute read write', 'execute write read', 'write execute read', 'write read execute', 'read write execute', 'read execute write', 'erw', 'ewr', 'wre', 'wer', 'rew', 'rwe']:
			return 64
		if Protection in ['PAGE_EXECUTE_WRITECOPY', 'execute copy write', 'execute write copy', 'write execute copy', 'write copy execute', 'copy write execute', 'copy execute write', 'ecw', 'ewc', 'wce', 'wec', 'cew', 'cwe']:
			return 128
		if Protection in ['PAGE_NOACCESS', 'noaccess', 'na', 'n']:
			return 1
		if Protection in ['PAGE_READONLY', 'readonly', 'ro', 'r']:
			return 2
		if Protection in ['PAGE_READWRITE', 'read write', 'write read', 'wr', 'rw']:
			return 4
		if Protection in ['PAGE_WRITECOPY', 'write copy', 'copy write', 'wc', 'cw']:
			return 8
		if Protection in ['PAGE_GUARD', 'pg', 'guard', 'g']:
			return 256
		if Protection in ['PAGE_NOCACHE', 'nc', 'nocache']:
			return 512
		if Protection in ['PAGE_WRITECOMBINE', 'write combine', 'combine write']:
			return 1024
		return Protection

	def Suspend(self, pid: int=None):
		kernel32 = ctypes.WinDLL('kernel32.dll')
		if pid:
			kernel32.DebugActiveProcess(pid)
		if self.PID:
			kernel32.DebugActiveProcess(self.PID)

	def Resume(self, pid: int=None):
		kernel32 = ctypes.WinDLL('kernel32.dll')
		if pid:
			kernel32.DebugActiveProcessStop(pid)
		if self.PID:
			kernel32.DebugActiveProcessStop(self.PID)
InjectorClass = InjectorClass()

def ReadRobloxString(ExpectedAddress: int) -> str:
	try:
		StringCount = InjectorClass.Pymem.read_int(ExpectedAddress + 16)
		if StringCount > 15:
			return InjectorClass.Pymem.read_string(InjectorClass.DRP(ExpectedAddress), StringCount)
		return InjectorClass.Pymem.read_string(ExpectedAddress, StringCount)
	except TypeError as e:
		exit()

def GetClassName(Instance: int) -> str:
	ExpectedAddress = InjectorClass.DRP(InjectorClass.DRP(Instance + 24) + 8)
	return ReadRobloxString(ExpectedAddress)

def setParent(Instance, Parent, parentOffset, childrenOffset):
	InjectorClass.Pymem.process_handle = ctypes.windll.kernel32.OpenProcess(2035711, False, InjectorClass.Pymem.process_id)
	PAGE_EXECUTE_READWRITE = 64
	ntdll = ctypes.windll.ntdll
	NtProtectVirtualMemory = ntdll.NtProtectVirtualMemory
	NtProtectVirtualMemory.restype = ctypes.c_long
	base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
	old_protect = ctypes.c_ulong()
	size = ctypes.c_size_t(4096)
	NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
	base_address = ctypes.windll.kernel32.GetModuleHandleW(None)
	NtProtectVirtualMemory(InjectorClass.Pymem.process_handle, ctypes.byref(ctypes.c_void_p(base_address)), ctypes.byref(size), old_protect, ctypes.byref(ctypes.c_ulong()))
	InjectorClass.Pymem.write_longlong(Instance + parentOffset, Parent)
	newChildren = InjectorClass.Pymem.allocate(1024)
	InjectorClass.Pymem.write_longlong(newChildren + 0, newChildren + 64)
	ptr = InjectorClass.Pymem.read_longlong(Parent + childrenOffset)
	childrenStart = InjectorClass.Pymem.read_longlong(ptr)
	childrenEnd = InjectorClass.Pymem.read_longlong(ptr + 8)
	if childrenStart == 0 or childrenEnd == 0 or childrenEnd <= childrenStart:
		exit()
	length = childrenEnd - childrenStart
	if length < 0:
		exit()
	b = InjectorClass.Pymem.read_bytes(childrenStart, length)
	InjectorClass.Pymem.write_bytes(newChildren + 64, b, len(b))
	e = newChildren + 64 + length
	InjectorClass.Pymem.write_longlong(e, Instance)
	InjectorClass.Pymem.write_longlong(e + 8, InjectorClass.Pymem.read_longlong(Instance + 16))
	e = e + 16
	InjectorClass.Pymem.write_longlong(newChildren + 8, e)
	InjectorClass.Pymem.write_longlong(newChildren + 16, e)

def GetViewRegex(folderPath, latestFile):
	filePath = folderPath + '\\' + latestFile
	regexPattern = comp('view\\((\\w+)\\)')
	try:
		with open(filePath, 'r', encoding='utf-8') as fileStream:
			print("Testing file..")
	except IOError:
		print(f'Failed to open file: {filePath}')
		for line in fileStream:
			match = regexPattern.search(line)
			if match:
				newAddress = int(match.group(1), 16)
				return newAddress

def readQword(process, address, value):
	try:
		value.value = process.read_ulonglong(address)
		return True
	except pymem.exception.MemoryReadError:
		exit()

def GetMethodModel():
	guiroot_pattern = b'\\x47\\x75\\x69\\x52\\x6F\\x6F\\x74\\x00\\x47\\x75\\x69\\x49\\x74\\x65\\x6D'
	guiroot_address = InjectorClass.AOBSCANALL(guiroot_pattern, xreturn_multiple=False)
	dataModel = InjectorClass.DRP(guiroot_address + 56) + 408 - 8
	if dataModel:
		return dataModel
	return None

def GetLatestFile(folderPath, file_filter=None):
	try:
		files = [f if os.path.isfile(os.path.join(folderPath, f)) else fx for fx in os.listdir(folderPath)]
	except Exception as e:
		print('Error:', e)
		if file_filter:
			files = [f for f in files if file_filter in f]
		latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(folderPath, f)))
		return latest_file

def GetDataModel():
	localAppData = os.environ.get('LOCALAPPDATA')
	if localAppData:
		folderPath = os.path.join(os.getenv('LOCALAPPDATA'), 'Roblox', 'logs')
		latestFile = GetLatestFile(folderPath, 'Player')
		process = pymem.Pymem('RobloxPlayerBeta.exe')
		RenderView = GetViewRegex(folderPath, latestFile)
		if RenderView:
			RandomAssShitlmao = ctypes.c_ulonglong(0)
			readQword(process, RenderView + 280, RandomAssShitlmao)
			DataModel = ctypes.c_ulonglong(0)
			if readQword(process, RandomAssShitlmao.value + 408, DataModel):
				game = DataModel.value
				return game

def Freeze():
	for proc in psutil.process_iter():
		if proc.name() == RobloxPlayer[0] or proc.name() == RobloxPlayer[1]:
			proc.suspend()

	for proc in psutil.process_iter():
		if proc.name() == RobloxPlayer[2]:
			proc.terminate()

def Resume():
	for proc in psutil.process_iter():
		if proc.name() == RobloxPlayer[0] or proc.name() == RobloxPlayer[1]:
			proc.resume()

	for proc in psutil.process_iter():
		if proc.name() == RobloxPlayer[2]:
			proc.terminate()

def execute():
	ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
	if not Injected:
		messagebox.showinfo('Comet BETA', 'Comet is currently not injected!')
		return
	for file in os.listdir(f'C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs'):
		try:
			os.remove(f'C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs/' + file)
		except:
			pass
	else:  # inserted
		pass  # postinserted
	ExecuteCode(text_box.get('1.0', tk.END))

def inject():
	global Injecting  # inserted
	global game  # inserted
	global Injected  # inserted
	root.title('Comet BETA | modded by k5utils - Attaching')
	ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
	if not Injecting or Injected:
		try:
			print('❗ Starting injection...')
			Injecting = True
			SpoofName = True
			InjectScript = False
			TargetScript = False
			print('✔ Waiting for target')
			while True:
				if InjectorClass.YieldForProgram(RobloxPlayer[0], True, 15):
					target = RobloxPlayer[0]
				else:  # inserted
					if InjectorClass.YieldForProgram(RobloxPlayer[1], True, 15):
						target = RobloxPlayer[1]
					else:  # inserted
						continue
			try:
				DataModel = GetDataModel()
				print(f'✔ Found DataModel: {DataModel}')
			except Exception as e:
				print(e)

				print(f'⚠ Failed using: {DataModelMethods[0]}, Trying {DataModelMethods[1]()}')
				try:
					DataModel = GetMethodModel()
				except Exception as e:
					print('⚠ Failed to inject')
					messagebox.showinfo('Comet BETA', 'Failed to Attach, please re-attach.')
			print('❗ Removing ROBLOX logs (OG MSG: Beginning next stage...)')
			for file in os.listdir(f'C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs'):
				try:
					os.remove(f'C:/Users/{os.getlogin()}/AppData/Local/Roblox/logs/' + file)
				except Exception as e:
					print("⚠ Couldn't remove log file (oh shit)")
					print(f"⚠ Error: {str(e)}")
					print()
		except Exception as e:
			print("Something bad happen'd, now we're going to close road bocks for uhh idk")
			print(f"Error: {str(e)}")
			for pid in (process.pid for process in psutil.process_iter() if process.name()in RobloxPlayer):
				os.kill(pid)
				print(f"🚑 Killed {pid}")
			print()
			raise e
		finally:  # inserted
			game = toInstance(DataModel)
			players = toInstance(game.FindFirstChild('Players'))
			localPlayer = toInstance(players.GetChildren()[0])
			localName = localPlayer.Name
			workspace = toInstance(game.FindFirstChild('Workspace'))
			playershit = toInstance(workspace.FindFirstChild(localName))
			humanoid = toInstance(playershit.FindFirstChild('Humanoid'))
			workspace = toInstance(game.GetChildren()[0])
			character_found = False
			character = toInstance(InjectorClass.Pymem.read_longlong(localPlayer.Self + 664))
			if character:
				character_found = True
			if not character_found:
				messagebox.showinfo('Comet BETA', 'Failed to find character, please re-attach.')
				Injecting = False
				Injected = False
			animateScript = character.findFirstClass('LocalScript')
			if animateScript is None:
				Injected = False
				Injecting = False
				messagebox.showinfo('Comet BETA', 'Failed to Attach, please re-attach.')
			TargetScript = toInstance(animateScript)
			InjectScript = None
			Freeze()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			results = InjectorClass.AOBSCANALL(LightingScript, True)
			Resume()
			print(results)
			if results == []:
				messagebox.showwarning('Comet BETA', 'Failed to get script! This usually happens when you dont use a teleport game')
				Injected = False
				Injecting = False
			for rn in results:
				result = rn
				bres = InjectorClass.d2h(result)
				aobs = ''
				for i in range(1, 17):
					aobs = aobs + bres[i - 1:i]
				aobs = InjectorClass.hex2le(aobs)
				first = False
				Freeze()
				res = InjectorClass.AOBSCANALL(aobs, True)
				Resume()
				if res:
					valid = False
					for i in res:
						result = i
						if InjectorClass.Pymem.read_longlong(result - NameOffset + 8) == result - NameOffset:
							InjectScript = result - NameOffset
							valid = True
							break
				if valid:
					break
			InjectScript = toInstance(InjectScript)
			Injected = True
			Injecting = False
			messagebox.showinfo('Comet BETA', 'Successfully attached, Reset to execute scripts!')
			Freeze()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			b = InjectorClass.Pymem.read_bytes(InjectScript.Self + 256, 336)
			Resume()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			InjectorClass.Pymem.write_bytes(TargetScript.Self + 256, b, len(b))
			Resume()

			coreGui = game.GetChildren()[31]
			root.title('Comet BETA - Attached')
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))

def open_file():
	file_path = filedialog.askopenfilename(filetypes=[('Lua Scripts', '*.lua'), ('Text Files', '*.txt'), ('All Files', '*.*')])
	if file_path:
		with open(file_path, 'r') as file:
			text_box.delete('1.0', tk.END)
			text_box.insert(tk.END, file.read())
		apply_highlighting()

def ExecuteCode(string):
	BridgeService = toInstance(game.findFirstChild('BridgeService'))
	StringValue = toInstance(BridgeService.findFirstChild('exe'))
	NewStringPtr = InjectorClass.Pymem.allocate(len(string))
	InjectorClass.Pymem.write_string(NewStringPtr, string)
	InjectorClass.Pymem.write_bytes(StringValue.Self + 208, bytes.fromhex(InjectorClass.hex2le(InjectorClass.d2h(len(string)))), 8)
	InjectorClass.Pymem.write_longlong(StringValue.Self + 192, NewStringPtr)

def save_file(scripts_listbox):
	file_path = filedialog.asksaveasfilename(defaultextension='.lua', filetypes=[('Lua Scripts', '*.lua'), ('Text Files', '*.txt'), ('All Files', '*.*')])
	if file_path:
		with open(file_path, 'w') as file:
			file.write(text_box.get('1.0', tk.END))
		load_scripts(scripts_listbox)

def load_scripts(scripts_listbox):
	scripts_folder = os.path.join(os.getcwd(), 'Scripts')
	if not os.path.exists(scripts_folder):
		os.makedirs(scripts_folder)
	scripts_listbox.delete(0, tk.END)
	for file_name in os.listdir(scripts_folder):
		if file_name.endswith('.txt') or file_name.endswith('.lua'):
			scripts_listbox.insert(tk.END, file_name)

def on_script_select(event):
	selected_file = scripts_listbox.get(scripts_listbox.curselection())
	scripts_folder = os.path.join(os.getcwd(), 'Scripts')
	file_path = os.path.join(scripts_folder, selected_file)
	with open(file_path, 'r') as file:
		text_box.delete('1.0', tk.END)
		text_box.insert(tk.END, file.read())
		apply_highlighting()

lua_keywords = '\\b(and|break|do|else|elseif|end|false|for|function|if|in|local|nil|not|or|repeat|return|then|true|until|while|hi)\\b'
lua_functions = '\\b(print|pairs|ipairs|next|tonumber|tostring|type|error|assert|pcall|xpcall|collectgarbage|require|module)\\b'
lua_comments = '(--[^\\n]*)'
lua_strings = '(\\\".*?\\\"|\\\'.*?\\\')'

def highlight_pattern(text, pattern, tag, start='1.0', end='end'):
	start = text.index(start)
	end = text.index(end)
	text.mark_set('matchStart', start)
	text.mark_set('matchEnd', start)
	text.mark_set('searchLimit', end)
	count = tk.IntVar()
	while True:
		index = text.search(pattern, 'matchEnd', 'searchLimit', count=count, regexp=True)
		if index == '':
			return
		text.mark_set('matchStart', index)
		text.mark_set('matchEnd', '%s+%sc' % (index, count.get()))
		text.tag_add(tag, 'matchStart', 'matchEnd')

def apply_highlighting(event=None):
	text_box.tag_remove('keyword', '1.0', 'end')
	text_box.tag_remove('function', '1.0', 'end')
	text_box.tag_remove('comment', '1.0', 'end')
	text_box.tag_remove('string', '1.0', 'end')
	highlight_pattern(text_box, lua_keywords, 'keyword')
	highlight_pattern(text_box, lua_functions, 'function')
	highlight_pattern(text_box, lua_comments, 'comment')
	highlight_pattern(text_box, lua_strings, 'string')

button_style={'font':('Helvetica',12),'bg':'lightblue','fg':'black','relief':'raised'}

root = tk.Tk()
root.title('Comet BETA | modded by k5utils - Unattached')
root.configure(bg='#121212')
root.geometry('650x250')
text_box = tk.Text(root, height=10, width=50, bg='#151515', fg='white', insertbackground='white', relief='flat', undo=True)
text_box.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')
text_box.tag_configure('keyword', foreground='orange')
text_box.tag_configure('function', foreground='blue')
text_box.tag_configure('comment', foreground='green')
text_box.tag_configure('string', foreground='yellow')
text_box.bind('<KeyRelease>', apply_highlighting)
placeholder_script = random.choice(['unc-test.lua', 'iy-reborn.lua'])
with open(f'Scripts\\{placeholder_script}', 'r') as f:
	text_box.insert(tk.END, f.read())
scripts_listbox = tk.Listbox(root, height=10, width=30, bg='#151515', fg='white', relief='flat', bd=1, highlightbackground='white')
scripts_listbox.grid(row=0, column=3, padx=10, pady=10, sticky='nsew')
scripts_listbox.bind('<<ListboxSelect>>', on_script_select)
load_scripts(scripts_listbox)
execute_button = tk.Button(root, text='Execute', command=execute, **button_style)
execute_button.grid(row=1, column=0, padx=10, pady=10, sticky='ew')
inject_button = tk.Button(root, text='Inject', command=inject, **button_style)
inject_button.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
open_file_button = tk.Button(root, text='Open File', command=open_file, **button_style)
open_file_button.grid(row=1, column=2, padx=10, pady=10, sticky='ew')
save_file_button = tk.Button(root, text='Save File', command=lambda: save_file(scripts_listbox), **button_style)
save_file_button.grid(row=1, column=3, padx=10, pady=10, sticky='ew')
root.mainloop()