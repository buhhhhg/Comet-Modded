from pyperclip import copy
import os

cmd_path = "time py -m nuitka "

print("Nuitka CLI Compiler (im too lazy to write a whole cmd line for compiling)")
print("Press ENTER or type \"none\" to skip some inputs")
print("NOTE: Things in these brackets; (<thing>) will occur when you press ENTER. (example: (skip))\n")

while True:
	python_file = str(input("Enter .py file path: "))
	print()

	if os.path.isfile(python_file):
		break
	else:
		print("File doesn't exist!\n")

cmd_path += f'{python_file} --standalone --onefile '

filename = str(input("Enter filename (defaults to .py name): "))
print()

if filename == '':
	filename = None

if filename:
	cmd_path += f'--output-filename=\"{filename}\" '

packages = str(input("Enter packages [seperate with , no spaces]: "))
print()

packages_list = packages.split(',')

for package in packages_list:
	if package == 'tkinter':
		print("[PKG] Tkinter detected! Enabling plugin instead.")
		cmd_path += '--enable-plugins=tk-inter '
		continue
	print(f"[PKG] Included package `{package}`")
	cmd_path += f'--follow-import-to={package} '

nofollow = str(input("Dont follow imports? (y/N) "))

if nofollow.lower() in ['y','yes']:
	nofollow = True
elif nofollow == '' or nofollow.lower() in ['n','no']:
	nofollow = False

if nofollow:
	cmd_path += '--nofollow-imports '

print()

show_memory = str(input("Show memory info? (Y/n) "))
print()

if show_memory == '' or show_memory.lower() in ['y','yes']:
	show_memory = True
elif show_memory.lower() in ['n','no']:
	show_memory = False

if show_memory:
	cmd_path += '--show-memory '

run = str(input("Run the file after compiling? (y/N) "))
print()

if run.lower() in ['y','yes']:
	run = True
elif run == '' or run.lower() in ['n','no']:
	run = False

if run:
	cmd_path += '--run '

public_use = str(input("For public use? (Y/n) "))
print()

if public_use == '' or public_use.lower() in ['y','yes']:
	public_use = True
elif public_use.lower() in ['n','no']:
	public_use = False

if public_use:
	cmd_path += "--deployment "

admin = str(input("Ask for admin? (y/N) "))
print()

if admin.lower() in ['y','yes']:
	admin = True
elif admin == '' or admin.lower() in ['n','no']:
	admin = False

if admin:
	cmd_path += '--windows-uac-admin '

bloat = str(input("Use anti-bloat? (Y/n) "))
print()

if bloat == '' or bloat.lower() in ['y','yes']:
	bloat = True
elif bloat.lower() in ['n','no']:
	bloat = False

if bloat:
	cmd_path += '--enable-plugins=anti-bloat '

while True:
	icon = str(input("Enter .exe to pull icon off of (skip): "))
	print()

	if icon.lower() == 'none' or icon == '':
		icon = str(input("Enter .ico path (none): "))
		print()

	if icon.lower() == 'none' or icon == '':
		icon = None

	if icon is None:
		print("No icon used")
		break
	elif icon[len(icon)-3:] == "ico":
		cmd_path += f'--windows-icon-from-ico=\"{icon}\" '
		break
	elif icon[len(icon)-3:] == "exe":
		cmd_path += f'--windows-icon-from-exe=\"{icon}\" '
		break
	else:
		print("Invalid icon format (ico/exe)")


company_name = str(input("Enter company name (none): "))
print()

if company_name.lower() == 'none' or company_name == '':
	company_name = None

if company_name:
	cmd_path += f"--company-name=\"{company_name}\" "


copyright = str(input("Enter copyright name (none): "))
print()

if copyright.lower() == 'none' or copyright == '':
	copyright = None

if copyright:
	cmd_path += f"--copyright=\"{copyright}\" "

trademark = str(input("Enter trademark name (none): "))
print()

if trademark.lower() == 'none' or trademark == '':
	trademark = None

if trademark:
	cmd_path += f"--trademarks=\"{trademark}\" "

product_name = str(input("Enter product name (default to filename): "))
print()

if product_name.lower() == 'none' or product_name == '':
	if filename:
		product_name = filename
	else:
		product_name = python_file.removesuffix('.py')

if product_name:
	cmd_path += f"--product-name=\"{product_name}\" "

print("WARN: Max 4 digits (0.0.0.0) allowed. Min 2 digits (0.0) allowed. Strings are not allowed. ")
file_ver = str(input("Enter file version (none): "))
print()

if file_ver.lower() == 'none' or file_ver == '':
	file_ver = None

if file_ver:
	cmd_path += f"--file-version={file_ver} "

file_desc = str(input("Enter file description (none, defaults to exe filename): "))
print()

if file_desc.lower() == 'none' or file_desc == '':
	file_desc = None

if file_desc:
	cmd_path += f"--file-description=\"{file_desc}\" "

copy(cmd_path)
print(cmd_path)
print("Copied to clipboard!")