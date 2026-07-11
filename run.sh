LOCAL_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

pushd $LOCAL_DIR
cp target/x86_64-unknown-uefi/debug/satus.efi esp/efi/boot/bootx64.efi
qemu-system-x86_64 $($LOCAL_DIR/qemu_settings.sh)
popd
