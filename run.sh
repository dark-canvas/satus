LOCAL_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

pushd $LOCAL_DIR
cp target/x86_64-unknown-uefi/debug/satus.efi esp/efi/boot/bootx64.efi
qemu-system-x86_64 -enable-kvm -m 2G \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS_4M.fd \
    -drive format=raw,file=fat:rw:esp \
    -serial file:output.log
popd
