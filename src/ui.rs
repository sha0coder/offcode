// ANSI color constants
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const CYAN: &str = "\x1b[36m";
pub const YELLOW: &str = "\x1b[33m";
pub const RED: &str = "\x1b[31m";
pub const WHITE: &str = "\x1b[37m";
pub const BRIGHT_GREEN: &str = "\x1b[92m";
pub const BRIGHT_CYAN: &str = "\x1b[96m";
pub const BRIGHT_YELLOW: &str = "\x1b[93m";

// Mascot: ╭──────────╮ = 12 chars (10 inside)
//   eyes :   ◉    ◉   = 2+1+4+1+2 = 10 ✓
//   smile:    ╰──╯    = 3+4+3     = 10 ✓

pub fn print_mascot(model: &str) {
    let version = env!("CARGO_PKG_VERSION");
    let fr = format!("{BRIGHT_CYAN}{BOLD}");
    let ey = format!("{WHITE}{BOLD}");
    let sm = format!("{BRIGHT_GREEN}{BOLD}");
    let br = format!("{WHITE}{BOLD}");
    let ac = format!("{BRIGHT_CYAN}");
    let d  = format!("{DIM}");
    let r  = RESET;

    println!();
    println!("      {fr}╭──────────╮{r}");
    println!("      {fr}│  {ey}◉{r}    {ey}◉{r}  {fr}│{r}   {br}offcode{r} {ac}v{version}{r}");
    println!("      {fr}│   {sm}╰──╯{r}   {fr}│{r}   {d}offline coding assistant{r}");
    println!("      {fr}╰──────────╯{r}   {d}model: {model}{r}");
    println!();
}
