all:
	cargo build --target x86_64-unknown-uefi

test:
	cargo test --target x86_64-unknown-uefi

clean:
	cargo clean --target x86_64-unknown-uefi

