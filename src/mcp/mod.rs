//! MCP 2025-06-18 transport exposing protocol-compatible `recall` and
//! `remember` tools.

mod protocol;
mod server;
mod tools;

pub use protocol::{JsonRpcError, JsonRpcResponse};
pub use server::{McpServer, PROTOCOL_VERSION};
pub use tools::{
    recall_tool, recall_tool_for, remember_tool, remember_tool_for, tool_list, tool_list_for,
};

#[cfg(test)]
mod tests;
