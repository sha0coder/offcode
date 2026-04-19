pub fn generate_diff(old_content: &str, new_content: &str) -> String {
    let old_lines: Vec<&str> = old_content.lines().collect();
    let new_lines: Vec<&str> = new_content.lines().collect();
    let mut out = String::new();
    let mut changed = false;
    let max_len = old_lines.len().max(new_lines.len());

    for i in 0..max_len {
        let old = old_lines.get(i).unwrap_or(&"");
        let new = new_lines.get(i).unwrap_or(&"");
        if old != new {
            changed = true;
            if !old.is_empty() {
                out.push_str(&format!("{}-  {}{}\n", crate::ui::RED, old, crate::ui::RESET));
            }
            if !new.is_empty() {
                out.push_str(&format!("{}+  {}{}\n", crate::ui::BRIGHT_GREEN, new, crate::ui::RESET));
            }
        }
    }

    if !changed {
        return format!("{}No changes detected.{}\n", crate::ui::DIM, crate::ui::RESET);
    }
    out
}
