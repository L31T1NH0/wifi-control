use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    io::{self, Stdout},
    process::Command,
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

type AppResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct ScanResult {
    networks: Vec<Network>,
    connected_ssid: Option<String>,
    active_device: Option<String>,
}

#[derive(Debug, Default)]
struct ActiveWifiInfo {
    ssids: HashSet<String>,
    device: Option<String>,
}

#[derive(Clone, Debug)]
struct Network {
    active: bool,
    bssid: String,
    ssid: String,
    security: String,
    signal: u8,
    channel: String,
    frequency: String,
    rate: String,
    saved_name: Option<String>,
}

impl Network {
    fn is_open(&self) -> bool {
        self.security.trim().is_empty() || self.security == "--"
    }

    fn lock_icon(&self) -> &'static str {
        if self.is_open() { "OPEN" } else { "LOCK" }
    }

    fn display_ssid(&self) -> &str {
        if self.ssid.is_empty() {
            "<rede oculta>"
        } else {
            &self.ssid
        }
    }
}

#[derive(Debug)]
enum Modal {
    Help(Vec<String>),
    Details(Vec<String>),
    Secret { ssid: String, password: String },
    Qr { ssid: String, lines: Vec<String> },
    ConfirmForget(Network),
}

#[derive(Default)]
struct App {
    networks: Vec<Network>,
    selected: usize,
    password: String,
    entering_password: bool,
    pending_network: Option<Network>,
    connection_rx: Option<Receiver<Result<String, String>>>,
    connected_ssid: Option<String>,
    active_device: Option<String>,
    filter: String,
    entering_filter: bool,
    modal: Option<Modal>,
    status: String,
    should_quit: bool,
}

impl App {
    fn selected_network(&self) -> Option<&Network> {
        let visible = self.visible_indices();
        if visible.contains(&self.selected) {
            self.networks.get(self.selected)
        } else {
            visible.first().and_then(|index| self.networks.get(*index))
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        let filter = self.filter.to_lowercase();
        self.networks
            .iter()
            .enumerate()
            .filter_map(|(index, network)| {
                if filter.is_empty() || network.ssid.to_lowercase().contains(&filter) {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    fn selected_visible_position(&self) -> Option<usize> {
        self.visible_indices()
            .iter()
            .position(|index| *index == self.selected)
    }

    fn normalize_selection_to_filter(&mut self) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = 0;
        } else if !visible.contains(&self.selected) {
            self.selected = visible[0];
        }
    }

    fn select_next(&mut self) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            return;
        }
        let position = visible
            .iter()
            .position(|index| *index == self.selected)
            .unwrap_or(0);
        self.selected = visible[(position + 1) % visible.len()];
    }

    fn select_previous(&mut self) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            return;
        }
        let position = visible
            .iter()
            .position(|index| *index == self.selected)
            .unwrap_or(0);
        self.selected = if position == 0 {
            visible[visible.len() - 1]
        } else {
            visible[position - 1]
        };
    }

    fn refresh(&mut self) {
        if self.connection_rx.is_some() {
            self.status = "Aguarde a conexao atual terminar antes de atualizar.".to_string();
            return;
        }

        match scan_networks() {
            Ok(scan) => {
                self.networks = scan.networks;
                self.connected_ssid = scan.connected_ssid;
                self.active_device = scan.active_device;
                if self.selected >= self.networks.len() {
                    self.selected = self.networks.len().saturating_sub(1);
                }
                self.normalize_selection_to_filter();
                let connected = self.connected_ssid.as_deref().or_else(|| {
                    self.networks
                        .iter()
                        .find(|network| network.active)
                        .map(|network| network.ssid.as_str())
                });
                self.status = match connected {
                    Some(ssid) if !ssid.is_empty() => {
                        format!(
                            "Conectado: {ssid}. {} rede(s) encontrada(s).",
                            self.networks.len()
                        )
                    }
                    Some(_) => {
                        format!(
                            "Conectado em rede oculta. {} rede(s) encontrada(s).",
                            self.networks.len()
                        )
                    }
                    None => format!(
                        "Desconectado. {} rede(s) encontrada(s).",
                        self.networks.len()
                    ),
                };
            }
            Err(err) => {
                self.status = format!("Erro ao escanear: {err}");
            }
        }
    }

    fn start_connect(&mut self) {
        if self.connection_rx.is_some() {
            self.status = "Ja existe uma tentativa de conexao em andamento.".to_string();
            return;
        }

        let Some(network) = self.selected_network().cloned() else {
            self.status = "Nenhuma rede selecionada.".to_string();
            return;
        };

        if network.active {
            self.status = format!("Voce ja esta conectado em {}.", network.ssid);
            return;
        }

        if network.saved_name.is_some() {
            self.connect(network, None);
            return;
        }

        if network.is_open() {
            self.connect(network, None);
            return;
        }

        self.password.clear();
        self.entering_password = true;
        self.pending_network = Some(network);
    }

    fn connect_pending(&mut self) {
        let Some(network) = self.pending_network.take() else {
            self.entering_password = false;
            return;
        };

        let password = self.password.clone();
        if password.is_empty() {
            self.pending_network = Some(network);
            self.status = "Digite a senha antes de conectar.".to_string();
            return;
        }

        self.password.clear();
        self.entering_password = false;
        self.connect(network, Some(password));
    }

    fn connect(&mut self, network: Network, password: Option<String>) {
        self.status = format!("Conectando em {}...", network.ssid);

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let ssid = network.ssid.clone();
            let result = connect_network(&network, password.as_deref())
                .map_err(|err| format!("Falha ao conectar em {ssid}: {err}"));
            let _ = tx.send(result);
        });
        self.connection_rx = Some(rx);
    }

    fn poll_connection(&mut self) {
        let Some(rx) = self.connection_rx.take() else {
            return;
        };

        match rx.try_recv() {
            Ok(Ok(message)) => {
                self.status = message;
                self.refresh_after_connection();
            }
            Ok(Err(err)) => {
                self.status = err;
            }
            Err(mpsc::TryRecvError::Empty) => {
                self.connection_rx = Some(rx);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.status = "A tentativa de conexao terminou sem resposta.".to_string();
            }
        }
    }

    fn refresh_after_connection(&mut self) {
        match scan_networks() {
            Ok(scan) => {
                self.networks = scan.networks;
                self.connected_ssid = scan.connected_ssid;
                self.active_device = scan.active_device;
                if self.selected >= self.networks.len() {
                    self.selected = self.networks.len().saturating_sub(1);
                }
                self.normalize_selection_to_filter();
            }
            Err(err) => {
                self.status = format!("Conectou, mas falhou ao atualizar redes: {err}");
            }
        }
    }

    fn disconnect(&mut self) {
        let Some(device) = self.active_device.clone() else {
            self.status = "Nenhum dispositivo Wi-Fi conectado para desconectar.".to_string();
            return;
        };

        match disconnect_device(&device) {
            Ok(message) => {
                self.status = message;
                self.refresh();
            }
            Err(err) => self.status = format!("Falha ao desconectar: {err}"),
        }
    }

    fn toggle_wifi(&mut self) {
        match toggle_wifi_radio() {
            Ok(message) => {
                self.status = message;
                self.refresh();
            }
            Err(err) => self.status = format!("Falha ao alternar Wi-Fi: {err}"),
        }
    }

    fn show_details(&mut self) {
        let Some(network) = self.selected_network().cloned() else {
            self.status = "Nenhuma rede selecionada.".to_string();
            return;
        };

        let mut details = network_details(&network);
        if network.active
            && let Some(device) = self.active_device.as_deref()
        {
            match device_details(device) {
                Ok(mut lines) => details.append(&mut lines),
                Err(err) => details.push(format!("Detalhes do dispositivo: {err}")),
            }
        }
        self.modal = Some(Modal::Details(details));
    }

    fn show_password(&mut self) {
        let Some(network) = self.selected_network().cloned() else {
            self.status = "Nenhuma rede selecionada.".to_string();
            return;
        };

        match network_password(&network) {
            Ok(password) => {
                self.modal = Some(Modal::Secret {
                    ssid: network.display_ssid().to_string(),
                    password,
                });
            }
            Err(err) => self.status = format!("Senha indisponivel: {err}"),
        }
    }

    fn show_qr(&mut self) {
        let Some(network) = self.selected_network().cloned() else {
            self.status = "Nenhuma rede selecionada.".to_string();
            return;
        };

        match wifi_qr_lines(&network) {
            Ok(lines) => {
                self.modal = Some(Modal::Qr {
                    ssid: network.display_ssid().to_string(),
                    lines,
                });
            }
            Err(err) => self.status = format!("QR indisponivel: {err}"),
        }
    }

    fn confirm_forget(&mut self) {
        let Some(network) = self.selected_network().cloned() else {
            self.status = "Nenhuma rede selecionada.".to_string();
            return;
        };

        if network.saved_name.is_none() {
            self.status = "Esta rede nao tem perfil salvo para esquecer.".to_string();
            return;
        }

        self.modal = Some(Modal::ConfirmForget(network));
    }

    fn forget_network(&mut self, network: Network) {
        match forget_saved_network(&network) {
            Ok(message) => {
                self.modal = None;
                self.status = message;
                self.refresh();
            }
            Err(err) => {
                self.modal = None;
                self.status = format!("Falha ao esquecer rede: {err}");
            }
        }
    }
}

fn main() -> AppResult<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|arg| arg == "-l" || arg == "--list") {
        print_networks()?;
        return Ok(());
    }

    let mut terminal = setup_terminal()?;
    let result = run(&mut terminal);
    restore_terminal(&mut terminal)?;
    result
}

fn print_help() {
    println!("wifi - controle de Wi-Fi no terminal");
    println!();
    println!("Uso:");
    println!("  wifi          abre a interface TUI");
    println!("  wifi --list   lista redes sem abrir a TUI");
    println!("  wifi --help   mostra esta ajuda");
    println!();
    println!("Atalhos na TUI:");
    println!("  r             atualizar redes");
    println!("  ↑/↓ ou k/j    navegar");
    println!("  Enter         conectar");
    println!("  /             filtrar por nome");
    println!("  d             desconectar");
    println!("  f             esquecer rede salva");
    println!("  w             ligar/desligar Wi-Fi");
    println!("  i             detalhes da rede");
    println!("  p             ver senha salva");
    println!("  Q             QR code da rede");
    println!("  q ou Esc      sair");
}

fn print_networks() -> AppResult<()> {
    let scan = scan_networks()?;
    for network in scan.networks {
        let ssid = if network.ssid.is_empty() {
            "<rede oculta>"
        } else {
            &network.ssid
        };
        println!(
            "{:>3}%  {:<5}  {:<5}  ch {:<3}  {}{}",
            network.signal,
            network.lock_icon(),
            if network.active {
                "ON"
            } else if network.saved_name.is_some() {
                "SAVED"
            } else {
                ""
            },
            network.channel,
            if network.active { "* " } else { "  " },
            ssid
        );
    }
    Ok(())
}

fn setup_terminal() -> AppResult<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> AppResult<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> AppResult<()> {
    let mut app = App::default();
    app.refresh();

    while !app.should_quit {
        app.poll_connection();
        terminal.draw(|frame| draw(frame, &app))?;

        if event::poll(Duration::from_millis(200))?
            && let Event::Key(key) = event::read()?
        {
            handle_key(&mut app, key);
        }
    }

    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    if key.kind != KeyEventKind::Press && key.kind != KeyEventKind::Repeat {
        return;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        app.should_quit = true;
        return;
    }

    if let Some(modal) = app.modal.take() {
        match modal {
            Modal::ConfirmForget(network) => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => app.forget_network(network),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Enter => {
                    app.status = "Esquecer rede cancelado.".to_string();
                }
                _ => app.modal = Some(Modal::ConfirmForget(network)),
            },
            other => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {}
                _ => app.modal = Some(other),
            },
        }
        return;
    }

    if app.entering_filter {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.entering_filter = false;
                app.normalize_selection_to_filter();
            }
            KeyCode::Backspace => {
                app.filter.pop();
                app.normalize_selection_to_filter();
            }
            KeyCode::Delete => {
                app.filter.clear();
                app.normalize_selection_to_filter();
            }
            KeyCode::Char(ch) => {
                app.filter.push(ch);
                app.normalize_selection_to_filter();
            }
            _ => {}
        }
        return;
    }

    if app.entering_password {
        match key.code {
            KeyCode::Esc => {
                app.entering_password = false;
                app.pending_network = None;
                app.password.clear();
                app.status = "Conexao cancelada.".to_string();
            }
            KeyCode::Enter => app.connect_pending(),
            KeyCode::Backspace => {
                app.password.pop();
            }
            KeyCode::Delete => {
                app.password.clear();
            }
            KeyCode::Char(ch) => app.password.push(ch),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('?') => app.modal = Some(Modal::Help(help_lines())),
        KeyCode::Char('r') => app.refresh(),
        KeyCode::Char('/') => {
            app.entering_filter = true;
            app.status = "Digite para filtrar. Enter aplica, Esc sai, Delete limpa.".to_string();
        }
        KeyCode::Char('d') => app.disconnect(),
        KeyCode::Char('f') => app.confirm_forget(),
        KeyCode::Char('w') => app.toggle_wifi(),
        KeyCode::Char('i') => app.show_details(),
        KeyCode::Char('p') => app.show_password(),
        KeyCode::Char('Q') => app.show_qr(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous(),
        KeyCode::Enter => app.start_connect(),
        _ => {}
    }
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
            Constraint::Length(5),
        ])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            "wifi",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        connected_indicator(app),
        Span::raw("  "),
        Span::raw("use as funcoes abaixo"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let visible_indices = app.visible_indices();
    let items: Vec<ListItem> = visible_indices
        .iter()
        .filter_map(|index| app.networks.get(*index))
        .map(|network| {
            let active = if network.active { "*" } else { " " };
            let saved = if network.active {
                "ON"
            } else if network.saved_name.is_some() {
                "SAVED"
            } else {
                ""
            };
            let signal = signal_bars(network.signal);
            ListItem::new(Line::from(vec![
                Span::styled(format!("{active} "), Style::default().fg(Color::Green)),
                Span::styled(
                    format!("{signal:<4} "),
                    Style::default().fg(signal_color(network.signal)),
                ),
                Span::styled(
                    format!("{:<5} ", network.lock_icon()),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(format!("{saved:<5} "), Style::default().fg(Color::Cyan)),
                Span::raw(network.display_ssid().to_string()),
                Span::styled(
                    format!("  {}%", network.signal),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    if !visible_indices.is_empty() {
        state.select(app.selected_visible_position());
    }

    let list_title = if app.filter.is_empty() {
        "Redes disponiveis".to_string()
    } else {
        format!("Redes disponiveis | filtro: {}", app.filter)
    };
    let list = List::new(items)
        .block(Block::default().title(list_title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, chunks[1], &mut state);

    let status = Paragraph::new(app.status.as_str())
        .wrap(Wrap { trim: true })
        .block(Block::default().title("Status").borders(Borders::ALL));
    frame.render_widget(status, chunks[2]);

    draw_actions(frame, chunks[3]);

    if app.entering_password {
        draw_password_popup(frame, area, app);
    }
    if app.entering_filter {
        draw_filter_popup(frame, area, app);
    }
    if let Some(modal) = &app.modal {
        draw_modal(frame, area, modal);
    }
}

fn draw_actions(frame: &mut Frame, area: Rect) {
    let actions = Paragraph::new(vec![
        Line::from(vec![
            key_span("Enter"),
            Span::raw(" conectar   "),
            key_span("r"),
            Span::raw(" atualizar   "),
            key_span("/"),
            Span::raw(" filtrar   "),
            key_span("i"),
            Span::raw(" detalhes   "),
            key_span("p"),
            Span::raw(" senha   "),
            key_span("Q"),
            Span::raw(" QR"),
        ]),
        Line::from(vec![
            key_span("d"),
            Span::raw(" desconectar   "),
            key_span("f"),
            Span::raw(" esquecer   "),
            key_span("w"),
            Span::raw(" ligar/desligar Wi-Fi   "),
            key_span("?"),
            Span::raw(" ajuda   "),
            key_span("q/Esc"),
            Span::raw(" sair"),
        ]),
    ])
    .wrap(Wrap { trim: true })
    .block(Block::default().title("Funcoes").borders(Borders::ALL));
    frame.render_widget(actions, area);
}

fn key_span(key: &'static str) -> Span<'static> {
    Span::styled(
        key,
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn connected_indicator(app: &App) -> Span<'static> {
    match app.connected_ssid.as_deref() {
        Some(ssid) if !ssid.is_empty() => Span::styled(
            format!("CONECTADO: {ssid}"),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Some(_) => Span::styled(
            "CONECTADO: rede oculta",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::styled("DESCONECTADO", Style::default().fg(Color::Red)),
    }
}

fn draw_password_popup(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(60, 30, area);
    let ssid = app
        .pending_network
        .as_ref()
        .map(|network| network.ssid.as_str())
        .unwrap_or("rede");
    let masked = "*".repeat(app.password.chars().count());
    let content = vec![
        Line::from(format!("Senha para: {ssid}")),
        Line::from(""),
        Line::from(format!("{masked}_")),
        Line::from(""),
        Line::from("Enter conecta, Esc cancela, Delete limpa"),
    ];

    frame.render_widget(Clear, popup);
    let paragraph = Paragraph::new(content)
        .alignment(Alignment::Center)
        .block(Block::default().title("Senha Wi-Fi").borders(Borders::ALL));
    frame.render_widget(paragraph, popup);
}

fn draw_filter_popup(frame: &mut Frame, area: Rect, app: &App) {
    let popup = centered_rect(60, 22, area);
    let content = vec![
        Line::from("Filtrar redes por nome"),
        Line::from(""),
        Line::from(format!("{}_", app.filter)),
        Line::from(""),
        Line::from("Enter aplica, Esc fecha, Delete limpa"),
    ];

    frame.render_widget(Clear, popup);
    let paragraph = Paragraph::new(content)
        .alignment(Alignment::Center)
        .block(Block::default().title("Filtro").borders(Borders::ALL));
    frame.render_widget(paragraph, popup);
}

fn draw_modal(frame: &mut Frame, area: Rect, modal: &Modal) {
    match modal {
        Modal::Help(lines) => draw_lines_modal(frame, area, "Ajuda", lines, 62, 58),
        Modal::Details(lines) => draw_lines_modal(frame, area, "Detalhes", lines, 72, 60),
        Modal::Secret { ssid, password } => {
            let lines = vec![
                format!("Rede: {ssid}"),
                String::new(),
                format!("Senha: {password}"),
                String::new(),
                "Enter/Esc fecha".to_string(),
            ];
            draw_lines_modal(frame, area, "Senha salva", &lines, 64, 32);
        }
        Modal::Qr { ssid, lines } => {
            let mut content = vec![format!("Rede: {ssid}"), String::new()];
            content.extend(lines.iter().cloned());
            content.push(String::new());
            content.push("Enter/Esc fecha".to_string());
            draw_lines_modal(frame, area, "QR Code", &content, 72, 78);
        }
        Modal::ConfirmForget(network) => {
            let lines = vec![
                format!("Esquecer perfil salvo de {}?", network.display_ssid()),
                String::new(),
                "y confirma, n/Esc cancela".to_string(),
            ];
            draw_lines_modal(frame, area, "Confirmar", &lines, 58, 24);
        }
    }
}

fn help_lines() -> Vec<String> {
    vec![
        "r        atualizar redes".to_string(),
        "setas    navegar".to_string(),
        "j/k      navegar".to_string(),
        "Enter    conectar".to_string(),
        "/        filtrar por nome".to_string(),
        "d        desconectar rede atual".to_string(),
        "f        esquecer rede salva".to_string(),
        "w        ligar/desligar Wi-Fi".to_string(),
        "i        detalhes da rede".to_string(),
        "p        ver senha salva".to_string(),
        "Q        QR code da rede".to_string(),
        "q/Esc    sair".to_string(),
        String::new(),
        "Enter/Esc fecha esta janela".to_string(),
    ]
}

fn draw_lines_modal(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: &[String],
    width: u16,
    height: u16,
) {
    let popup = centered_rect(width, height, area);
    let content: Vec<Line> = lines.iter().map(|line| Line::from(line.clone())).collect();

    frame.render_widget(Clear, popup);
    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: false })
        .block(Block::default().title(title).borders(Borders::ALL));
    frame.render_widget(paragraph, popup);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn signal_bars(signal: u8) -> &'static str {
    match signal {
        0..=24 => ".",
        25..=49 => "..",
        50..=74 => "...",
        _ => "....",
    }
}

fn signal_color(signal: u8) -> Color {
    match signal {
        0..=35 => Color::Red,
        36..=65 => Color::Yellow,
        _ => Color::Green,
    }
}

fn scan_networks() -> AppResult<ScanResult> {
    let saved_profiles = saved_wifi_profiles()?;
    let active = active_wifi_info()?;
    let output = Command::new("nmcli")
        .args([
            "--wait",
            "15",
            "-t",
            "-f",
            "ACTIVE,BSSID,SSID,SECURITY,SIGNAL,CHAN,FREQ,RATE",
            "device",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    let networks = parse_networks(
        &String::from_utf8_lossy(&output.stdout),
        &saved_profiles,
        &active.ssids,
    );
    let connected_ssid = active.ssids.iter().next().cloned();

    Ok(ScanResult {
        networks,
        connected_ssid,
        active_device: active.device,
    })
}

fn parse_networks(
    output: &str,
    saved_profiles: &HashMap<String, String>,
    active_ssids: &HashSet<String>,
) -> Vec<Network> {
    let mut networks: Vec<Network> = output
        .lines()
        .filter_map(|line| parse_network(line, saved_profiles))
        .collect();
    if !networks.iter().any(|network| network.active) {
        for network in &mut networks {
            if active_ssids.contains(&network.ssid) {
                network.active = true;
            }
        }
    }
    sort_networks(&mut networks);
    networks
}

fn sort_networks(networks: &mut [Network]) {
    networks.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| b.signal.cmp(&a.signal))
            .then_with(|| b.saved_name.is_some().cmp(&a.saved_name.is_some()))
            .then_with(|| a.ssid.cmp(&b.ssid))
            .then_with(|| a.bssid.cmp(&b.bssid))
    });
}

fn parse_network(line: &str, saved_profiles: &HashMap<String, String>) -> Option<Network> {
    let parts = split_nmcli_line(line);
    if parts.len() < 5 {
        return None;
    }

    Some(Network {
        active: parts[0] == "yes",
        bssid: parts[1].clone(),
        ssid: parts[2].clone(),
        security: parts[3].clone(),
        signal: parts[4].parse().unwrap_or(0),
        channel: parts.get(5).cloned().unwrap_or_default(),
        frequency: parts.get(6).cloned().unwrap_or_default(),
        rate: parts.get(7).cloned().unwrap_or_default(),
        saved_name: saved_profiles.get(&parts[2]).cloned(),
    })
}

fn active_wifi_info() -> AppResult<ActiveWifiInfo> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    let mut info = ActiveWifiInfo::default();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let parts = split_nmcli_line(line);
        if parts.len() < 2 || parts[1] != "802-11-wireless" {
            continue;
        }

        let name = parts[0].clone();
        let ssid = saved_profile_ssid(&name)
            .ok()
            .flatten()
            .unwrap_or_else(|| name.clone());
        if !ssid.is_empty() {
            info.ssids.insert(ssid);
        }
        if info.device.is_none() {
            info.device = parts.get(2).filter(|device| !device.is_empty()).cloned();
        }
    }
    Ok(info)
}

fn saved_wifi_profiles() -> AppResult<HashMap<String, String>> {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "NAME,TYPE", "connection", "show"])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    let wifi_profile_names = parse_wifi_profile_names(&String::from_utf8_lossy(&output.stdout));
    let mut profiles = HashMap::new();
    for name in wifi_profile_names {
        let ssid = saved_profile_ssid(&name)
            .ok()
            .flatten()
            .unwrap_or_else(|| name.clone());
        if !ssid.is_empty() {
            profiles.insert(ssid, name);
        }
    }
    Ok(profiles)
}

fn parse_wifi_profile_names(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let parts = split_nmcli_line(line);
            if parts.len() >= 2 && parts[1] == "802-11-wireless" {
                Some(parts[0].clone())
            } else {
                None
            }
        })
        .collect()
}

fn saved_profile_ssid(profile_name: &str) -> AppResult<Option<String>> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "802-11-wireless.ssid",
            "connection",
            "show",
            "id",
            profile_name,
        ])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    Ok(parse_saved_profile_ssid(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_saved_profile_ssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let parts = split_nmcli_line(line);
        if parts.len() >= 2 && parts[0] == "802-11-wireless.ssid" {
            Some(parts[1].clone())
        } else {
            None
        }
    })
}

fn split_nmcli_line(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            ':' => {
                parts.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if escaped {
        current.push('\\');
    }
    parts.push(current);
    parts
}

fn connect_network(network: &Network, password: Option<&str>) -> AppResult<String> {
    if network.ssid.is_empty() {
        return Err("nao consigo conectar em rede oculta sem SSID.".into());
    }

    let mut command = Command::new("nmcli");
    command.args(["--wait", "20"]);

    if password.is_none()
        && let Some(saved_name) = &network.saved_name
    {
        command.args(["connection", "up", "id", saved_name]);
        return run_connect_command(command, &network.ssid);
    }

    command.args(["device", "wifi", "connect", &network.ssid]);

    if let Some(password) = password
        && !password.is_empty()
    {
        command.args(["password", password]);
    }

    if !network.bssid.is_empty() {
        command.args(["bssid", &network.bssid]);
    }

    run_connect_command(command, &network.ssid)
}

fn disconnect_device(device: &str) -> AppResult<String> {
    let output = Command::new("nmcli")
        .args(["--wait", "10", "device", "disconnect", device])
        .output()?;
    command_message(output, "Desconectado.")
}

fn toggle_wifi_radio() -> AppResult<String> {
    let current = Command::new("nmcli").args(["radio", "wifi"]).output()?;
    if !current.status.success() {
        return Err(String::from_utf8_lossy(&current.stderr)
            .trim()
            .to_string()
            .into());
    }

    let enabled = String::from_utf8_lossy(&current.stdout).trim() == "enabled";
    let next = if enabled { "off" } else { "on" };
    let output = Command::new("nmcli")
        .args(["radio", "wifi", next])
        .output()?;
    command_message(
        output,
        if enabled {
            "Wi-Fi desligado."
        } else {
            "Wi-Fi ligado."
        },
    )
}

fn forget_saved_network(network: &Network) -> AppResult<String> {
    let Some(saved_name) = network.saved_name.as_deref() else {
        return Err("rede sem perfil salvo.".into());
    };

    let output = Command::new("nmcli")
        .args(["connection", "delete", "id", saved_name])
        .output()?;
    command_message(
        output,
        &format!("Rede esquecida: {}", network.display_ssid()),
    )
}

fn network_password(network: &Network) -> AppResult<String> {
    if network.is_open() {
        return Ok("<rede aberta, sem senha>".to_string());
    }

    let Some(saved_name) = network.saved_name.as_deref() else {
        return Err("so consigo mostrar senha de rede salva.".into());
    };

    let output = Command::new("nmcli")
        .args([
            "-s",
            "-g",
            "802-11-wireless-security.psk",
            "connection",
            "show",
            "id",
            saved_name,
        ])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if password.is_empty() {
        Err("senha nao encontrada no perfil salvo.".into())
    } else {
        Ok(password)
    }
}

fn wifi_qr_lines(network: &Network) -> AppResult<Vec<String>> {
    if network.ssid.is_empty() {
        return Err("QR de rede oculta ainda precisa do SSID real.".into());
    }

    let payload = wifi_qr_payload(network, &network_password(network)?);
    let output = Command::new("qrencode")
        .args(["-t", "UTF8", "-m", "1", &payload])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

fn wifi_qr_payload(network: &Network, password: &str) -> String {
    let ssid = escape_wifi_qr_value(&network.ssid);
    if network.is_open() {
        format!("WIFI:T:nopass;S:{ssid};;")
    } else {
        let auth = if network.security.contains("WEP") {
            "WEP"
        } else {
            "WPA"
        };
        let password = escape_wifi_qr_value(password);
        format!("WIFI:T:{auth};S:{ssid};P:{password};;")
    }
}

fn escape_wifi_qr_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' | ';' | ',' | ':' | '"' => vec!['\\', ch],
            _ => vec![ch],
        })
        .collect()
}

fn network_details(network: &Network) -> Vec<String> {
    vec![
        format!("SSID: {}", network.display_ssid()),
        format!(
            "Status: {}",
            if network.active {
                "conectada"
            } else {
                "disponivel"
            }
        ),
        format!("BSSID: {}", empty_dash(&network.bssid)),
        format!("Seguranca: {}", empty_dash(&network.security)),
        format!("Sinal: {}%", network.signal),
        format!("Canal: {}", empty_dash(&network.channel)),
        format!("Frequencia: {}", empty_dash(&network.frequency)),
        format!("Taxa: {}", empty_dash(&network.rate)),
        format!(
            "Perfil salvo: {}",
            network.saved_name.as_deref().unwrap_or("-")
        ),
    ]
}

fn device_details(device: &str) -> AppResult<Vec<String>> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "GENERAL.DEVICE,GENERAL.HWADDR,GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS",
            "device",
            "show",
            device,
        ])
        .output()?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }

    let mut lines = vec![String::new(), "Dispositivo".to_string()];
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let parts = split_nmcli_line(line);
        if parts.len() >= 2 {
            lines.push(format!("{}: {}", parts[0], parts[1]));
        }
    }
    Ok(lines)
}

fn empty_dash(value: &str) -> &str {
    if value.trim().is_empty() { "-" } else { value }
}

fn run_connect_command(mut command: Command, ssid: &str) -> AppResult<String> {
    let output = command.output()?;
    command_message(output, &format!("Conectado em {ssid}."))
}

fn command_message(output: std::process::Output, fallback: &str) -> AppResult<String> {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        if stdout.is_empty() {
            Ok(fallback.to_string())
        } else {
            Ok(stdout)
        }
    } else if stderr.is_empty() {
        Err("nmcli retornou erro sem mensagem.".into())
    } else {
        Err(stderr.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(ssid: &str, profile: &str) -> HashMap<String, String> {
        HashMap::from([(ssid.to_string(), profile.to_string())])
    }

    fn test_network(ssid: &str, security: &str) -> Network {
        Network {
            active: false,
            bssid: "AA:BB".to_string(),
            ssid: ssid.to_string(),
            security: security.to_string(),
            signal: 80,
            channel: "6".to_string(),
            frequency: "2437 MHz".to_string(),
            rate: "130 Mbit/s".to_string(),
            saved_name: None,
        }
    }

    #[test]
    fn split_nmcli_line_preserves_escaped_colons_and_backslashes() {
        assert_eq!(
            split_nmcli_line(r"yes:AA\:BB\:CC:Casa\:Sala:WPA2:87"),
            vec!["yes", "AA:BB:CC", "Casa:Sala", "WPA2", "87"]
        );
        assert_eq!(split_nmcli_line(r"name\\"), vec![r"name\".to_string()]);
    }

    #[test]
    fn parse_network_handles_saved_profile_and_open_security() {
        let profiles = saved("Cafe Livre", "perfil-cafe");
        let network = parse_network(r"no:AA\:BB:Cafe Livre:--:72", &profiles).unwrap();

        assert!(!network.active);
        assert_eq!(network.bssid, "AA:BB");
        assert_eq!(network.ssid, "Cafe Livre");
        assert!(network.is_open());
        assert_eq!(network.saved_name.as_deref(), Some("perfil-cafe"));
    }

    #[test]
    fn parse_network_rejects_incomplete_rows() {
        assert!(parse_network("no:missing:fields", &HashMap::new()).is_none());
    }

    #[test]
    fn parse_saved_profile_ssid_uses_real_ssid_field() {
        let output = "802-11-wireless.ssid:Rede\\:Casa\n";
        assert_eq!(
            parse_saved_profile_ssid(output).as_deref(),
            Some("Rede:Casa")
        );
    }

    #[test]
    fn parse_wifi_profile_names_filters_non_wifi_profiles() {
        let output = "Minha Rede:802-11-wireless\nlo:loopback\nCabo:802-3-ethernet\n";
        assert_eq!(parse_wifi_profile_names(output), vec!["Minha Rede"]);
    }

    #[test]
    fn parse_networks_orders_active_then_signal_then_saved() {
        let profiles = saved("Saved Weak", "Saved Weak");
        let networks = parse_networks(
            "\
no:22:Open Strong:--:95
yes:11:Connected:WPA2:40
no:33:Saved Weak:WPA2:30
",
            &profiles,
            &HashSet::new(),
        );

        let ssids: Vec<&str> = networks
            .iter()
            .map(|network| network.ssid.as_str())
            .collect();
        assert_eq!(ssids, vec!["Connected", "Open Strong", "Saved Weak"]);
        assert!(networks[0].active);
        assert_eq!(networks[2].saved_name.as_deref(), Some("Saved Weak"));
    }

    #[test]
    fn parse_networks_marks_active_from_connection_ssid_even_when_scan_says_no() {
        let active_ssids = HashSet::from(["Casa".to_string()]);
        let networks = parse_networks(
            "no:11:Casa:WPA2:80\nno:22:Outra:WPA2:90\n",
            &HashMap::new(),
            &active_ssids,
        );

        assert_eq!(networks[0].ssid, "Casa");
        assert!(networks[0].active);
        assert!(!networks[1].active);
    }

    #[test]
    fn wifi_qr_payload_escapes_reserved_characters() {
        let network = test_network(r#"Casa: "A", Sala; 2\G"#, "WPA2");

        assert_eq!(
            wifi_qr_payload(&network, r#"pa:ss;word,1"2\3"#),
            r#"WIFI:T:WPA;S:Casa\: \"A\"\, Sala\; 2\\G;P:pa\:ss\;word\,1\"2\\3;;"#
        );
    }

    #[test]
    fn wifi_qr_payload_handles_open_network() {
        let network = test_network("Aberta", "--");

        assert_eq!(wifi_qr_payload(&network, ""), "WIFI:T:nopass;S:Aberta;;");
    }

    #[test]
    fn connect_pending_keeps_prompt_open_when_password_is_empty() {
        let network = test_network("Secure", "WPA2");
        let mut app = App {
            entering_password: true,
            pending_network: Some(network),
            ..App::default()
        };

        app.connect_pending();

        assert!(app.entering_password);
        assert!(app.pending_network.is_some());
        assert!(app.connection_rx.is_none());
        assert_eq!(app.status, "Digite a senha antes de conectar.");
    }
}
