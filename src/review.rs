//! `agentbox review`: cargo-insta style review of the single pending request.

use std::io::IsTerminal;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::client::{Client, format_diff};
use crate::proto::*;

const HELP: &str = "a: accept   r: reject   d: closure diff   j/k: scroll   q: quit";

/// What the human decided in the TUI.
enum Decision {
    Accept,
    Reject { reason: String },
    Quit,
}

struct Review<'a> {
    client: &'a Client,
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

impl Review<'_> {
    fn draw(&self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        let footer = match &self.reason {
            Some(text) => format!("reject reason: {text}▏  (Enter: send, Esc: cancel)"),
            None => HELP.to_owned(),
        };

        terminal.draw(|frame| {
            let layout = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]);
            let [body, bar] = layout.areas(frame.area());

            let lines: Vec<Line> = self.lines.iter().map(|line| styled(line)).collect();
            frame.render_widget(Paragraph::new(lines).scroll((self.scroll, 0)), body);

            let bar_style = Style::new().add_modifier(Modifier::REVERSED);
            frame.render_widget(Paragraph::new(footer).style(bar_style), bar);
        })?;

        Ok(())
    }

    /// Appends the package-level closure diff below what is already shown.
    fn show_closure_diff(&mut self) {
        let request = ClosureDiffRequest {
            target: self.client.target(),
            ..Default::default()
        };
        let result = self
            .client
            .block_on(self.client.daemon.closure_diff(request));

        let text = match result.map(|response| response.into_owned().text) {
            Ok(text) if text.trim().is_empty() => "(no package-level differences)".to_owned(),
            Ok(text) => text,
            Err(error) => format!("{error:#}"),
        };

        self.lines.push("# closure diff".into());
        self.lines.extend(text.lines().map(str::to_owned));
    }

    /// Handles a key while typing the rejection reason.
    fn reason_key(&mut self, key: KeyCode) -> Option<Decision> {
        let text = self.reason.as_mut()?;

        match key {
            KeyCode::Enter => {
                return Some(Decision::Reject {
                    reason: std::mem::take(text),
                });
            }
            KeyCode::Esc => self.reason = None,
            KeyCode::Backspace => drop(text.pop()),
            KeyCode::Char(c) => text.push(c),
            _ => {}
        }

        None
    }

    fn key(&mut self, key: KeyCode) -> Option<Decision> {
        if self.reason.is_some() {
            return self.reason_key(key);
        }

        match key {
            KeyCode::Char('a') => return Some(Decision::Accept),
            KeyCode::Char('q') | KeyCode::Esc => return Some(Decision::Quit),
            KeyCode::Char('r') => self.reason = Some(String::new()),
            KeyCode::Char('d') => self.show_closure_diff(),
            KeyCode::Char('j') | KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Char(' ') | KeyCode::PageDown => self.scroll = self.scroll.saturating_add(20),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(20),
            _ => {}
        }

        None
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<Decision> {
        loop {
            self.draw(terminal)?;

            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if let Some(decision) = self.key(key.code) {
                return Ok(decision);
            }
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

    let mut review = Review {
        client,
        lines: format_diff(diff),
        scroll: 0,
        reason: None,
    };
    let mut terminal = ratatui::init();
    let decision = review.run(&mut terminal);
    ratatui::restore();

    match decision? {
        Decision::Quit => Ok(()),
        Decision::Reject { reason } => crate::client::decide(client, false, reason),
        Decision::Accept => {
            println!("building and applying…");
            crate::client::decide(client, true, String::new())
        }
    }
}
