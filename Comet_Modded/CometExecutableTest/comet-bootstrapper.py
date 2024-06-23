import wget, sys, socket, os, shutil, psutil
from pathlib import Path
from colorama import init
from rich.console import Console

console = Console(color_system="truecolor")

init()

scripts_list = ["iy-reborn.lua","unc-test.lua"]

comet_ascii_text = """
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓██████████████▓▒░░▒▓████████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░    ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░         ░▒▓█▓▒░     
 ░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░  ░▒▓█▓▒░     
																		  
																		  
"""

console.print(comet_ascii_text, style="bold bright_black")

old_path = os.getcwd()

cancel_kill = False
no_choice = False
for proc in psutil.process_iter(['name']):
	if proc.info['name'] == 'CometModded.exe':
		if no_choice is False:
			console.print("⚠ Comet is already running! Would you like to continue? (Y/n) ")
			choice = str(input())
			if choice.lower() in ['yes','y','']:
				no_choice = True
				continue
			elif choice.lower() in ['n','no']:
				cancel_kill = True
				break
		proc.terminate()
		proc.wait()

if cancel_kill:
	sys.exit()

try:
	socket.create_connection(("8.8.8.8", 53), timeout=5)
except OSError:
	console.print("⚠ You aren't connected to the internet! Re-run the bootstrapper when you're connected.", style="bold red")
	sys.exit(1)
except Exception as e:
	console.print("⚠ Send a DM to k5utils with a screenshot of this! ⚠", style="bold white on red")
	console.print(f"Error: {str(e)}", style="bold red")
	console.print("Phase: CheckInternetConnected", style="bold red")
	sys.exit(1)


def download_github_file(file):
	try:
		wget.download(f"https://raw.githubusercontent.com/buhhhhg/Comet-Modded/main/{file}")
		console.print("\n")
	except Exception as e:
		if e.reason.strerror == "getaddrinfo failed":
			console.print("⚠ Failed to download, you've been disconnected from the internet", style="bold red")
			sys.exit(1)

comet_directory = os.path.join(old_path, 'CometModded')

if not os.path.isdir(comet_directory):
	try:
		os.mkdir(comet_directory)
		console.print("[-] Made comet folder", style="bold italic bright_black")
	except Exception as e:
		console.print("\n")
		console.print("⚠ Send a DM to k5utils with a screenshot of this! ⚠", style="bold white on red")
		console.print(f"Error: {str(e)}", style="bold red")
		console.print("Phase: CreateCometFolder", style="bold red")
		console.print("\n")
		sys.exit(1)

os.chdir(comet_directory)

scripts = os.path.join(comet_directory, 'Scripts')

if not os.path.isdir(scripts):
	try:
		os.mkdir(scripts)
		console.print("[-] Made scripts folder", style="bold italic bright_black")
	except Exception as e:
		console.print("\n")
		console.print("⚠ Send a DM to k5utils with a screenshot of this! ⚠", style="bold white on red")
		console.print(f"Error: {str(e)}", style="bold red")
		console.print("Phase: CreateScriptsFolder", style="bold red")
		console.print("\n")
		sys.exit(1)

os.chdir(scripts)

for file in scripts_list:
	if os.path.isfile(os.path.join(scripts, file)):
		scripts_list.remove(file)

if scripts_list:
	console.print("[-] Downloading scripts..", style="bold italic bright_black")
	for i, file in enumerate(scripts_list):
		console.print("[-] Downloading",file, style="bold bright_black")
		download_github_file(file)
		if i == len(scripts_list):
			break
		console.print("\n")

os.chdir(comet_directory)

comet_assets = os.path.join(comet_directory, 'CometAssets')

if not os.path.isdir(comet_assets):
	try:
		os.mkdir(comet_assets)
		console.print("[-] Made Comet Assets folder", style="bold italic bright_black")
	except Exception as e:
		console.print("\n")
		console.print("⚠ Send a DM to k5utils with a screenshot of this! ⚠", style="bold white on red")
		console.print(f"Error: {str(e)}", style="bold red")
		console.print("Phase: CreateAssetsFolder", style="bold red")
		console.print("\n")
		sys.exit(1)

console.print("\n")
if not os.path.isfile(os.path.join(comet_directory, 'CometModded.exe')):
	console.print("[-] Downloading main executor..", style="bold italic bright_black")
	download_github_file('CometModded.exe')

if os.path.isfile('version'):
	os.chdir(os.getenv('TEMP'))
	download_github_file('version')

	old_version_path = os.getenv('USERPROFILE')+'\\version'
	new_version_path = os.getenv('TEMP')+'\\version'

	with open(old_version_path) as f:
		old_version = f.read()

	with open(new_version_path) as f:
		new_version = f.read()

	os.remove(old_version_path)
	shutil.move(new_version_path, old_version_path.removesuffix('version'))

	if old_version != new_version:
		console.print("\n")
		console.print(f"[❗] A new version of Comet Modded ({new_version}) has been found!", style="bold green")
		console.print("[❗] Downloading new version..", style="bold italic bright_black")
		console.print("\n")
		os.chdir(comet_directory)
		os.remove('CometModded.exe')
		download_github_file('CometModded.exe')

psutil.Popen([f'{str(comet_directory)}\\CometModded.exe'])

console.print("\n")
console.print("[-] Press Enter to continue . . . ", style="bold bright_black")
input()
sys.exit(0)