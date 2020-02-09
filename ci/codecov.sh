#!/bin/bash
set -ex

cd "$(dirname "$0")/.."

sudo apt-get update
sudo apt-get install libbfd-dev libdw-dev libelf-dev libcurl4-openssl-dev libbfd-dev libiberty-dev
wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
tar xzf master.tar.gz
cd kcov-master
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=~/.local
make -j`nproc`
make install
export PATH=~/.local/bin:$PATH
cd ../..
rm -rf kcov-master master.tar.gz
for file in target/debug/deps/{bidirectional,latency_exchange,lossy_connect,lossy,message_splitting,multiplexer,not_enough_latency,rendezvous,single_packet_tsbpd,srt,stransmit_cmdline}-*; do
    if [[ -x "$file" ]]; then
        echo Doing kcov for $file
        mkdir -p "target/cov/$(basename $file)"
        kcov --exclude-pattern=/.cargo,/usr/lib,/usr/include,/lib,tests/ --verify "target/cov/$(basename $file)" "$file"
    fi
done
bash <(curl -s https://codecov.io/bash)
echo "Uploaded code coverage"
