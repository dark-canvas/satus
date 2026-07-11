LOCAL_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

pushd $LOCAL_DIR
cp target/x86_64-unknown-uefi/debug/satus.efi esp/efi/boot/bootx64.efi
qemu-system-x86_64 -enable-kvm $($LOCAL_DIR/qemu_settings.sh) -S -s &
#sleep 5
#gdb -ex "target remote localhost:1234" -ex "add-symbol-file esp/efi/boot/kernel.elf 0xFFFFFF8000000000" -ex "b kernel::_start"
popd
