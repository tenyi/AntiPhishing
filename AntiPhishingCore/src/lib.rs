//! AntiPhishing 共用判定核心：設定結構、郵件解析與評分、LLM 判定、IMAP 操作、.eml 評估。
//! CLI（`anti-phishing`）與 GUI（`anti-phishing-gui`）共用，修改此處即同時影響兩版。

pub mod config;
pub mod eval;
pub mod llm;
pub mod mail;
pub mod mailbox;

pub use config::*;
pub use eval::*;
pub use llm::*;
pub use mail::*;
pub use mailbox::*;

#[cfg(test)]
mod tests;
