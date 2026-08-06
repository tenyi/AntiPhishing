fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("AntiPhishing.ico");
        if let Err(e) = res.compile() {
            eprintln!("Warning: failed to compile winres icon: {e}");
        }
    }
}
