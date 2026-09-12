fn main() {
    // crypt(3) lives in libxcrypt on modern Fedora/Bazzite (libcrypt.so.2).
    println!("cargo:rustc-link-lib=crypt");
}
