#!/bin/bash
set -ex

sudo apt-get update
sudo apt-get install libbfd-dev libdw-dev libelf-dev
wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
tar xzf master.tar.gz
cd kcov-master
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=~/.local
make
make install
export PATH=~/.local/bin:$PATH
cd ../..
rm -rf kcov-master master.tar.gz
for file in target/debug/{bidirectional,latency_exchange,lossy_connect,lossy,message_splitting,multiplexer,not_enough_latency,single_packet_tsbpd,srt,stransmit_cmdline}-*[^\.d]
    do mkdir -p "target/cov/$(basename $file)"; kcov --exclude-pattern=/.cargo,/usr/lib,tests/ --verify "target/cov/$(basename $file)" "$file"
done
bash <(curl -s https://codecov.io/bash)
echo "Uploaded code coverage"
