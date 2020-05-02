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

run_test() {
    testname=$1
    for testexec in target/release/${testname}-*; do
        if [ -x $testexec ]; then 
            echo Doing kcov for $testexec
            mkdir -p "target/cov/$(basename $testexec)"
            kcov --exclude-pattern=/.cargo,/usr/lib,/usr/include,/lib,tests/ --verify "target/cov/$(basename $testexec)" "$testexec"
        fi
    done
}

# Run each rust file in tests
run_test srt
for testpath in tests/*.rs; do
    testfile="$(basename $testpath)"
    testname="${testfile%.*}"
    run_test $testname
done

bash <(curl -s https://codecov.io/bash)
echo "Uploaded code coverage"
