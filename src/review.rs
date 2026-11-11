//! `agentbox review`: cargo-insta style review of the single pending request.

use std::io::IsTerminal;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::client::{Client, format_diff};
use crate::proto::*;

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

pub fn run(client: &Client, json: bool) -> anyhow::Result<()> {
    let target = client.target.clone();
    let res: PendingRes = client.call("GetPending", &target)?;
    if json || !std::io::stdout().is_terminal() {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(());
    }
    for note in &res.notes {
        println!("{note}");
    }
    let Some(diff) = res.pending else {
        println!("no pending request for this directory");
        return Ok(());
    };

    let mut lines = format_diff(&diff);
    let mut scroll: u16 = 0;
    // Some(text) while typing a rejection reason.
    let mut reason: Option<String> = None;
    let mut terminal = ratatui::init();
    let decision = loop {
        let footer = match &reason {
            Some(text) => format!("reject reason: {text}▏  (Enter: send, Esc: cancel)"),
            None => "a: accept   r: reject   d: closure diff   j/k: scroll   q: quit".into(),
        };
        terminal.draw(|f| {
            let [body, bar] =
                Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(f.area());
            f.render_widget(
                Paragraph::new(lines.iter().map(|l| styled(l)).collect::<Vec<_>>())
                    .scroll((scroll, 0)),
                body,
            );
            f.render_widget(
                Paragraph::new(footer).style(Style::new().add_modifier(Modifier::REVERSED)),
                bar,
            );
        })?;
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(text) = &mut reason {
            match key.code {
                KeyCode::Enter => break Some((false, std::mem::take(text))),
                KeyCode::Esc => reason = None,
                KeyCode::Backspace => drop(text.pop()),
                KeyCode::Char(c) => text.push(c),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('a') => break Some((true, String::new())),
            KeyCode::Char('r') => reason = Some(String::new()),
            KeyCode::Char('q') | KeyCode::Esc => break None,
            KeyCode::Char('d') => {
                let text = match client.call::<_, TextRes>("ClosureDiff", &target) {
                    Ok(res) if res.text.trim().is_empty() => {
                        "(no package-level differences)".into()
                    }
                    Ok(res) => res.text,
                    Err(e) => format!("{e:#}"),
                };
                lines.push("# closure diff".into());
                lines.extend(text.lines().map(str::to_owned));
            }
            KeyCode::Char('j') | KeyCode::Down => scroll = scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => scroll = scroll.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char(' ') => scroll = scroll.saturating_add(20),
            KeyCode::PageUp => scroll = scroll.saturating_sub(20),
            _ => {}
        }
    };
    ratatui::restore();
    if let Some((accept, reason)) = decision {
        if accept {
            println!("building and applying…");
        }
        let res: TextRes = client.call(
            "Decide",
            &DecideReq {
                target,
                accept,
                reason,
            },
        )?;
        println!("{}", res.text);
    }
    Ok(())
}
