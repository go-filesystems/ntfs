#!/bin/sh
# Regenerate the mkntfs cross-compat fixture.
#
# Requires the Linux ntfs-3g / ntfsprogs reference tool `mkntfs` on PATH
# (also shipped by macOS Homebrew as part of the `ntfs-3g` formula).
#
# Output: image.ntfs.gz next to this script, plus EXPECTED.txt md5s
# refreshed to match the contents written below.
#
# Usage: sh testdata/mkntfs/regen.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
img="$here/image.ntfs"

if ! command -v mkntfs >/dev/null 2>&1; then
	echo "regen.sh: mkntfs not on PATH; install ntfs-3g (or ntfsprogs)" >&2
	exit 1
fi

# 20 MiB is the smallest size mkntfs reliably accepts. The compressed
# .gz that the test loads is much smaller (mostly zero pages).
size_mib=20
rm -f "$img" "$img.gz"
dd if=/dev/zero of="$img" bs=1M count=$size_mib >/dev/null 2>&1
mkntfs -F -Q -L compat "$img" >/dev/null

# Populate via ntfs-3g + a loop mount, OR via ntfscp (preferred — no
# kernel mount needed). The fixture writes two known files; the md5s
# below MUST match EXPECTED.txt.

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
printf 'hello\n' > "$tmpdir/hello.txt"
# Deterministic 1 KiB "random" blob matching math/rand seed=1 in Go.
go run "$here/blobgen.go" "$tmpdir/blob.bin"

if command -v ntfscp >/dev/null 2>&1; then
	ntfscp "$img" "$tmpdir/hello.txt" /hello.txt
	# ntfscp does not create directories; use ntfs-3g mount as fallback.
	mnt=$(mktemp -d)
	ntfs-3g "$img" "$mnt"
	mkdir -p "$mnt/sub"
	cp "$tmpdir/blob.bin" "$mnt/sub/blob.bin"
	umount "$mnt"
	rmdir "$mnt"
else
	mnt=$(mktemp -d)
	ntfs-3g "$img" "$mnt"
	cp "$tmpdir/hello.txt" "$mnt/hello.txt"
	mkdir -p "$mnt/sub"
	cp "$tmpdir/blob.bin" "$mnt/sub/blob.bin"
	umount "$mnt"
	rmdir "$mnt"
fi

gzip -9 "$img"
echo "wrote $img.gz ($(wc -c < "$img.gz") bytes)"
