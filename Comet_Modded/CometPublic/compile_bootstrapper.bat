@echo off

py -m nuitka comet-bootstrapper.py --standalone --onefile --output-filename="CometBootstrapper" --follow-import-to=wget --follow-import-to=sys --follow-import-to=socket --follow-import-to=os --follow-import-to=shutil --follow-import-to=pathlib --follow-import-to=colorama --follow-import-to=rich --follow-import-to=keyboard --show-memory --deployment --enable-plugins=anti-bloat --windows-icon-from-ico="C:\Users\kuda\Downloads\cometlogo.ico" --product-name="CometBootstrapper" --file-version=0.0.0.1 --file-description="Auto-downloads the latest Comet version. | Made by k5utils" 