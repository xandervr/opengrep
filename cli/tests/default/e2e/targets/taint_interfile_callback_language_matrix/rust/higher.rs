fn apply_callback<F: Fn(String) -> String>(callback: F) -> String { callback(get_input()) }
