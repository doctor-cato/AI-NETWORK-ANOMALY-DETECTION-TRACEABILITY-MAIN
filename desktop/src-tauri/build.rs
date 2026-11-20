fn main() {
    println!("cargo:rerun-if-env-changed=NETFLOW_OOD_GATE_SHA256");
    tauri_build::build()
}
