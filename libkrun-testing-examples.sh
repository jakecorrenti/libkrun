#!/bin/bash

# This is a script to move around the necessary files so that I can make changes
# to the source code and test them with the boot_efi libkrun example

make clean
sh build_on_krunvm.sh
EFI=1 make

cp target/release/libkrun-efi.dylib examples/
rm /opt/homebrew/opt/libkrun-efi/lib/libkrun-efi.*
rm /opt/homebrew/opt/libkrun-efi/lib/pkgconfig/libkrun.pc

cp target/release/libkrun-efi.* /opt/homebrew/opt/libkrun-efi/lib/
cp libkrun.pc /opt/homebrew/opt/libkrun-efi/lib/pkgconfig/

cd examples
make clean
make boot_efi
# boots the raw image (which is currently supported. we want to get to the point that it boots from a sparse file)
./boot_efi ~/Downloads/fedora-coreos-40.20240728.3.0-metal.aarch64.raw
