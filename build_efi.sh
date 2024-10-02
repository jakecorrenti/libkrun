#!/bin/bash

make clean
sh build_on_krunvm.sh
make EFI=1
sudo make EFI=1 install

cp target/release/libkrun-efi.dylib examples/
rm /opt/homebrew/opt/libkrun-efi/lib/libkrun-efi.*
rm /opt/homebrew/opt/libkrun-efi/lib/pkgconfig/libkrun.pc
cp target/release/libkrun-efi.* /opt/homebrew/opt/libkrun-efi/lib/
cp libkrun.pc /opt/homebrew/opt/libkrun-efi/lib/pkgconfig/

cd examples
make clean
make EFI=1
./boot_efi ~/Downloads/fedora.qcow2
