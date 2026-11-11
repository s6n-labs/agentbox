//! `agentbox review`: cargo-insta style review of the single pending request.
//!
//! [`Review`] is the screen: its state, how it reacts to keys and how it is drawn. It
//! knows neither the terminal nor the daemon, so it can be tested with ratatui's
//! `TestBackend`. [`run`] connects it to both.

use std::io::IsTerminal;

use agentbox::proto::{ClosureDiffRequest, Diff, GetPendingRequest};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};

use super::client::{Client, decide, format_diff};

const HELP: &str = "a: accept   r: reject   d: closure diff   j/k: scroll   q: quit";

/// Lines scrolled by `PageUp` / `PageDown`.
const PAGE: u16 = 20;

/// What the human decided.
#[derive(Debug, PartialEq)]
enum Decision {
    Accept,
    Reject { reason: String },
    Quit,
}

/// What the event loop has to do after a key press.
#[derive(Debug, PartialEq)]
enum Step {
    /// Nothing; just redraw.
    Continue,
    /// Ask the daemon for the closure diff and show it.
    FetchClosureDiff,
    Done(Decision),
}

struct Review {
    lines: Vec<String>,
    scroll: u16,
    /// `Some` while the human is typing why they reject.
    reason: Option<String>,
}

fn styled(line: &str) -> Line<'_> {
    let style = match line.as_bytes().first() {
        Some(b'#') => Style::new().add_modifier(Modifier::BOLD),
        Some(b'@') => Style::new().fg(Color::Cyan),
        Some(b'+') => Style::new().fg(Color::Green),
        Some(b'-') => Style::new().fg(Color::Red),
        _ if line.starts_with("add ") => Style::new().fg(Color::Green),
        _ if line.starts_with("remove ") => Style::new().fg(Color::Red),
        _ if line.starts_with("replace ") => Style::new().fg(Color::Yellow),
        _ => Style::new(),
    };

    Line::styled(line, style)
}

impl Review {
    fn new(diff: &Diff) -> Self {
        Self {
            lines: format_diff(diff),
            scroll: 0,
            reason: None,
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let layout = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]);
        let [body, bar] = layout.areas(frame.area());

        let lines: Vec<Line> = self.lines.iter().map(|line| styled(line)).collect();
        frame.render_widget(Paragraph::new(lines).scroll((self.scroll, 0)), body);

        let footer = match &self.reason {
            Some(text) => format!("reject reason: {text}▏  (Enter: send, Esc: cancel)"),
            None => HELP.to_owned(),
        };
        let bar_style = Style::new().add_modifier(Modifier::REVERSED);
        frame.render_widget(Paragraph::new(footer).style(bar_style), bar);
    }

    /// Appends the package-level closure diff below what is already shown.
    fn show_closure_diff(&mut self, text: &str) {
        self.lines.push("# closure diff".into());

        if text.trim().is_empty() {
            self.lines.push("(no package-level differences)".into());
            return;
        }

        self.lines.extend(text.lines().map(str::to_owned));
    }

    /// Handles a key while the rejection reason is being typed.
    fn reason_key(&mut self, key: KeyCode) -> Step {
        let Some(text) = &mut self.reason else {
            return Step::Continue;
        };

        match key {
            KeyCode::Enter => {
                let reason = std::mem::take(text);
                return Step::Done(Decision::Reject { reason });
            }
            KeyCode::Esc => self.reason = None,
            KeyCode::Backspace => drop(text.pop()),
            KeyCode::Char(c) => text.push(c),
            _ => {}
        }

        Step::Continue
    }

    fn key(&mut self, key: KeyCode) -> Step {
        // While typing, letters are text, not commands.
        if self.reason.is_some() {
            return self.reason_key(key);
        }

        match key {
            KeyCode::Char('a') => return Step::Done(Decision::Accept),
            KeyCode::Char('q') | KeyCode::Esc => return Step::Done(Decision::Quit),
            KeyCode::Char('d') => return Step::FetchClosureDiff,
            KeyCode::Char('r') => self.reason = Some(String::new()),
            KeyCode::Char('j') | KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Char(' ') | KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(PAGE);
            }
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(PAGE),
            _ => {}
        }

        Step::Continue
    }
}

/// Asks the daemon for the closure diff of the pending request.
fn fetch_closure_diff(client: &Client) -> String {
    let request = ClosureDiffRequest {
        target: client.target(),
        ..Default::default()
    };

    match client.block_on(client.daemon.closure_diff(request)) {
        Ok(response) => response.into_owned().text,
        Err(error) => format!("{error:#}"),
    }
}

/// Runs the screen on the terminal until the human decides.
fn event_loop(
    review: &mut Review,
    client: &Client,
    terminal: &mut DefaultTerminal,
) -> std::io::Result<Decision> {
    loop {
        terminal.draw(|frame| review.draw(frame))?;

        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match review.key(key.code) {
            Step::Continue => {}
            Step::FetchClosureDiff => review.show_closure_diff(&fetch_closure_diff(client)),
            Step::Done(decision) => return Ok(decision),
        }
    }
}

pub fn run(client: &Client, json: bool) -> anyhow::Result<()> {
    let request = GetPendingRequest {
        target: client.target(),
        ..Default::default()
    };
    let response = client
        .block_on(client.daemon.get_pending(request))?
        .into_owned();

    if json || !std::io::stdout().is_terminal() {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }

    for note in &response.notes {
        println!("{note}");
    }
    let Some(diff) = response.pending.as_option() else {
        println!("no pending request for this directory");
        return Ok(());
    };

    let mut review = Review::new(diff);
    let mut terminal = ratatui::init();
    let decision = event_loop(&mut review, client, &mut terminal);
    ratatui::restore();

    match decision? {
        Decision::Quit => Ok(()),
        Decision::Reject { reason } => decide(client, false, reason),
        Decision::Accept => {
            println!("building and applying…");
            decide(client, true, String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use agentbox::proto::PatchOperation;
    use insta::assert_snapshot;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    /// A request that adds a domain and a package.
    fn diff() -> Diff {
        let text_diff = "\
--- a/flake.nix
+++ b/flake.nix
@@ -3,3 +3,3 @@
   devShells.default = pkgs.mkShell {
-    packages = [ pkgs.cargo ];
+    packages = [ pkgs.cargo pkgs.jq ];
   };
";

        Diff {
            reason: Some("need jq and GitHub access".into()),
            policy_patch: vec![PatchOperation {
                op: "add".into(),
                path: "/network/allow/2".into(),
                value: Some("\"github.com:443\"".into()),
                ..Default::default()
            }],
            text_diff: text_diff.into(),
            derivation_changed: true,
            ..Default::default()
        }
    }

    /// Draws the screen on an in-memory terminal of the given size.
    fn render(review: &Review, width: u16, height: u16) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| review.draw(frame)).unwrap();

        terminal
    }

    fn type_text(review: &mut Review, text: &str) {
        for c in text.chars() {
            assert_eq!(review.key(KeyCode::Char(c)), Step::Continue);
        }
    }

    #[test]
    fn shows_the_request() {
        let review = Review::new(&diff());

        assert_snapshot!(render(&review, 70, 14).backend());
    }

    #[test]
    fn scrolls_long_diffs() {
        let mut review = Review::new(&diff());

        for _ in 0..4 {
            review.key(KeyCode::Char('j'));
        }
        review.key(KeyCode::Up);

        assert_eq!(review.scroll, 3);
        assert_snapshot!(render(&review, 70, 8).backend());
    }

    #[test]
    fn scrolling_stops_at_the_top() {
        let mut review = Review::new(&diff());

        review.key(KeyCode::Char('k'));
        review.key(KeyCode::PageUp);
        assert_eq!(review.scroll, 0);

        review.key(KeyCode::PageDown);
        assert_eq!(review.scroll, PAGE);
    }

    #[test]
    fn asks_for_a_reason_when_rejecting() {
        let mut review = Review::new(&diff());

        assert_eq!(review.key(KeyCode::Char('r')), Step::Continue);
        type_text(&mut review, "use curl instead");

        assert_snapshot!(render(&review, 70, 14).backend());
    }

    #[test]
    fn enter_sends_the_typed_reason() {
        let mut review = Review::new(&diff());

        review.key(KeyCode::Char('r'));
        type_text(&mut review, "nop");
        review.key(KeyCode::Backspace);
        type_text(&mut review, "t needed");

        assert_eq!(
            review.key(KeyCode::Enter),
            Step::Done(Decision::Reject {
                reason: "not needed".into()
            })
        );
    }

    #[test]
    fn command_keys_are_plain_text_in_a_reason() {
        let mut review = Review::new(&diff());

        // `a`, `q` and `d` must not accept, quit or fetch while typing.
        review.key(KeyCode::Char('r'));
        type_text(&mut review, "a quick draft");

        assert_eq!(review.reason.as_deref(), Some("a quick draft"));
    }

    #[test]
    fn escape_cancels_the_reason_but_not_the_review() {
        let mut review = Review::new(&diff());

        review.key(KeyCode::Char('r'));
        type_text(&mut review, "hmm");
        assert_eq!(review.key(KeyCode::Esc), Step::Continue);
        assert_eq!(review.reason, None);

        // Back in command mode, the same keys are commands again.
        assert_eq!(review.key(KeyCode::Char('a')), Step::Done(Decision::Accept));
    }

    #[test]
    fn accept_and_quit_end_the_review() {
        let key = |code| Review::new(&diff()).key(code);

        assert_eq!(key(KeyCode::Char('a')), Step::Done(Decision::Accept));
        assert_eq!(key(KeyCode::Char('q')), Step::Done(Decision::Quit));
        assert_eq!(key(KeyCode::Esc), Step::Done(Decision::Quit));
        assert_eq!(key(KeyCode::Char('x')), Step::Continue);
    }

    #[test]
    fn the_closure_diff_is_appended_on_request() {
        let mut review = Review::new(&diff());

        assert_eq!(review.key(KeyCode::Char('d')), Step::FetchClosureDiff);
        review.show_closure_diff("jq: ∅ → 1.7.1, +1.2 MiB\n");
        review.scroll = 9;

        assert_snapshot!(render(&review, 70, 8).backend());
    }

    #[test]
    fn an_empty_closure_diff_says_so() {
        let mut review = Review::new(&diff());

        review.show_closure_diff("\n");

        assert_eq!(
            review.lines[review.lines.len() - 2..],
            ["# closure diff", "(no package-level differences)"]
        );
    }

    #[test]
    fn additions_are_green_and_removals_red() {
        let review = Review::new(&diff());
        let terminal = render(&review, 70, 14);
        let buffer = terminal.backend().buffer();

        // The first cell of a row carries the style of its line.
        let color_of = |text: &str| {
            let row = review.lines.iter().position(|line| line == text).unwrap();
            buffer[(0, u16::try_from(row).unwrap())].fg
        };

        assert_eq!(
            color_of("add /network/allow/2 \"github.com:443\""),
            Color::Green
        );
        assert_eq!(
            color_of("+    packages = [ pkgs.cargo pkgs.jq ];"),
            Color::Green
        );
        assert_eq!(color_of("-    packages = [ pkgs.cargo ];"), Color::Red);
        assert_eq!(color_of("@@ -3,3 +3,3 @@"), Color::Cyan);
    }

    #[test]
    fn the_help_bar_stays_on_the_last_row() {
        let review = Review::new(&diff());
        let terminal = render(&review, 70, 5);
        let buffer = terminal.backend().buffer();

        let last_row: String = (0..70).map(|x| buffer[(x, 4)].symbol()).collect();

        assert!(last_row.starts_with("a: accept"), "{last_row}");
        assert!(buffer[(0, 4)].modifier.contains(Modifier::REVERSED));
    }
}
