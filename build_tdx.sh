make clean
make TDX=1
sudo make TDX=1 install

cd examples
make clean
make TDX=1
LD_LIBRARY_PATH=/usr/local/lib64 ./launch-tee ~/tdx-testing/rhel.img tdx-config-noattest.json snp-example-data-disk.img
cd ../
