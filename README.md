# shadowsocksrr-rust

Rust 重写的 ShadowsocksR 现代（误）服务端，复刻以下协议逻辑：

- obfs: `tls1.2_ticket_auth`
- protocol: `auth_chain_d` / `auth_chain_e` / `auth_chain_f`
- protocol: `auth_akarin_rand` / `auth_akarin_spec_a`

## 设计范围

- 外层加密仅支持 `none`
- 改进了静默状态导致监听行为过于怪异的问题
- 修正了 `tls1.2_ticket_auth` 行为不合规的问题
- 修正了 `auth_akarin_spec_a` mss错误的问题

## 运行

1. 安装 Rust
2. 创建配置：

```bash
cp config.example.toml config.toml
```

3. 启动：

```bash
cargo run --release -- --config config.toml
```

## 配置

见 `config.example.toml`。

## 致谢
[shadowsocksrr/shadowsocksr](https://github.com/shadowsocksrr/shadowsocksr)

## License

Portions of this project are derived from ShadowsocksR and Shadowsocks, which are licensed under the Apache License, Version 2.0. A copy of the Apache License 2.0 is included in this repository as required by its terms.

Copyright (c) respective authors.

A copy of the Apache License 2.0 is included in this repository.
