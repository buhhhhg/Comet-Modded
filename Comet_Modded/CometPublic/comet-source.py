global Injected  # inserted
global Injecting  # inserted

print("Comet Modded - Modded by k5utils")
print("Anti-debugger has been removed")
print()

import os,sys,random,string,json,pymem,psutil,ctypes,base64,subprocess

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, PhotoImage
from ttkthemes import ThemedTk

from re import compile as comp
from re import escape

from time import sleep

old_path = os.getcwd()

if not os.path.isfile('version'):
	messagebox.showerror("Error occured", "Version file not found, re-run the bootstrapper!")
	sys.exit(1)

if not os.path.isdir('CometAssets'):
	messagebox.showerror("Error occured", "CometAssets folder not found, re-run the bootstrapper!")
	sys.exit(1)

if os.path.isdir('CometAssets'):
	os.chdir('CometAssets')
	if not os.path.isfile('cometwindowicon.png'):
		messagebox.showerror("Error occured", "CometAssets has been tampered with, re-run the bootstrapper!")
		sys.exit(1)
	os.chdir(old_path)

	# if not os.path.isdir('comet'):

# from ctypes import windll
# from ctypes import c_int
# from ctypes import c_uint
# from ctypes import c_ulong
# from ctypes import POINTER
# from ctypes import byref
# un-comment if shit doesnt work

LightingScript = '496E6A656374????????????????????06'
RobloxPlayer = ['RobloxPlayerModded.exe', 'Windows10Universal.exe', 'RobloxCrashHandler.exe']
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
		process = pymem.Pymem('RobloxPlayerModded.exe')
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
		messagebox.showinfo('Comet Modded', 'Comet is currently not injected!')
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
	root.title('Comet Modded | modded by k5utils - Attaching')
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
					messagebox.showinfo('Comet Modded', 'Failed to Attach, please re-attach.')
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
				messagebox.showinfo('Comet Modded', 'Failed to find character, please re-attach.')
				Injecting = False
				Injected = False
			animateScript = character.findFirstClass('LocalScript')
			if animateScript is None:
				Injected = False
				Injecting = False
				messagebox.showinfo('Comet Modded', 'Failed to Attach, please re-attach.')
			TargetScript = toInstance(animateScript)
			InjectScript = None
			Freeze()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			results = InjectorClass.AOBSCANALL(LightingScript, True)
			Resume()
			print(results)
			if results == []:
				messagebox.showwarning('Comet Modded', 'Failed to get script! This usually happens when you dont use a teleport game')
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
			messagebox.showinfo('Comet Modded', 'Successfully attached, Reset to execute scripts!')
			Freeze()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			b = InjectorClass.Pymem.read_bytes(InjectScript.Self + 256, 336)
			Resume()
			ctypes.windll.kernel32.SetConsoleTitleW(''.join((random.choice(string.ascii_lowercase) for _ in range(2000))))
			InjectorClass.Pymem.write_bytes(TargetScript.Self + 256, b, len(b))
			Resume()

			coreGui = game.GetChildren()[31]
			root.title('Comet Modded - Attached')
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
	count = ttk.IntVar()
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

comet_raw_image = "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"

style = ttk.Style()

style.configure('Comet.Button',
                font=('Verdana', 12),
                background='black',
                foreground='white',
                relief='raised')

style.map('Comet.Button',
          background=[('pressed', 'black'), ('active', 'black')],
          foreground=[('pressed', 'white'), ('active', 'white')])

root = ThemedTk("black")
root.title('Comet Modded | modded by k5utils - Unattached')
root.configure(bg='#121212')
root.geometry('650x250')
root.iconphoto(False, os.path.join("CometAssets", "cometwindowicon.png"))

text_box = tk.Text(root, height=10, width=50, bg='#151515', fg='white', insertbackground='white', relief='flat', undo=True)
text_box.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')
text_box.tag_configure('keyword', foreground='orange')
text_box.tag_configure('function', foreground='blue')
text_box.tag_configure('comment', foreground='green')
text_box.tag_configure('string', foreground='yellow')
text_box.bind('<KeyRelease>', apply_highlighting)

try:
	placeholder_script = random.choice(['unc-test.lua', 'iy-reborn.lua'])
	with open(f'Scripts\\{placeholder_script}', 'r') as f:
		text_box.insert(tk.END, f.read())
except FileNotFoundError:
	text_box.insert(tk.END, "print('Hello, world!')")
	pass
apply_highlighting()

scripts_listbox = tk.Listbox(root, height=10, width=30, bg='#151515', fg='white', relief='flat', bd=1, highlightbackground='white')
scripts_listbox.grid(row=0, column=3, padx=10, pady=10, sticky='nsew')
scripts_listbox.bind('<<ListboxSelect>>', on_script_select)
load_scripts(scripts_listbox)
execute_button = ttk.Button(root, text='Execute', command=execute, style='Comet.Button')
execute_button.grid(row=1, column=0, padx=10, pady=10, sticky='ew')
inject_button = ttk.Button(root, text='Inject', command=inject, style='Comet.Button')
inject_button.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
open_file_button = ttk.Button(root, text='Open File', command=open_file, style='Comet.Button')
open_file_button.grid(row=1, column=2, padx=10, pady=10, sticky='ew')
save_file_button = ttk.Button(root, text='Save File', command=lambda: save_file(scripts_listbox), style='Comet.Button')
save_file_button.grid(row=1, column=3, padx=10, pady=10, sticky='ew')
root.mainloop()