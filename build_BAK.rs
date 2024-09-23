fn main() {
    pkg_config::Config::new().probe("unicorn").unwrap();
    println!("cargo::rerun-if-changed=build.rs");
}
