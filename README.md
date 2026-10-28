# wifi-control

Gerenciador de Wi-Fi para terminal Linux, escrito em Rust com Ratatui. Usa o NetworkManager para listar redes, conectar, desconectar, esquecer perfis e ligar ou desligar o rádio. Também mostra detalhes, senhas de redes salvas e QR codes para compartilhar a conexão.

## Compilar e usar

Requer Rust com suporte à edição 2024, NetworkManager em execução e `nmcli` no PATH. Para gerar QR codes, instale também `qrencode`. As operações seguem as permissões do NetworkManager no sistema.

```sh
cargo build --release --locked
./target/release/wifi-control
```

## Teclas

- `↑`/`↓` ou `j`/`k`: selecionar rede; `Enter`: conectar.
- `/`: filtrar; `r`: atualizar; `i`: detalhes.
- `d`: desconectar; `f`: esquecer uma rede salva; `w`: alternar o rádio Wi-Fi.
- `p`: mostrar senha salva; `Q`: mostrar QR code.
- `?`: ajuda; `q` ou `Esc`: sair.
