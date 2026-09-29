from __future__ import annotations

SUBSYSTEM_RULES = {
    "configuration": ("Configuration", ("config", "configuration", "campaign", "parse_config")),
    "network_c2": ("Network / C2", ("c2", "beacon", "http", "winhttp", "wininet", "internet", "socket", "connect", "request", "response", "url", "domain", "urldownload")),
    "persistence": ("Persistence", ("run_key", "autorun", "persistence", "regsetvalue", "startup", "scheduled", "service")),
    "execution": ("Execution", ("execute", "shell", "shellexecute", "process", "createprocess", "command", "spawn")),
    "injection": ("Injection", ("inject", "writeprocessmemory", "createremotethread", "virtualallocex")),
    "discovery": ("Discovery", ("hostname", "username", "system_information", "enumerate", "os_version", "computer")),
    "collection": ("Collection", ("collect", "screenshot", "clipboard", "keylog", "file_collection")),
    "credential_access": ("Credential Access", ("credential", "password", "token", "browser_cookie")),
    "defense_evasion": ("Defense Evasion", ("evasion", "anti_debug", "antidebug", "sandbox", "disable", "sleep", "ping", "self_delete", "delete", "hidden")),
    "crypto_encoding": ("Crypto / Encoding", ("decrypt", "encrypt", "crypto", "aes", "rc4", "xor", "base64", "hash")),
    "file_operations": ("File Operations", ("file", "writefile", "readfile", "download", "upload", "path")),
    "registry_operations": ("Registry Operations", ("registry", "regopen", "regset", "regdelete", "hkcu", "hklm")),
    "process_operations": ("Process Operations", ("process", "openprocess", "terminateprocess", "snapshot")),
    "service_operations": ("Service Operations", ("service", "createservice", "startservice")),
    "loader_initialization": ("Loader / Initialization", ("init", "initialize", "loader", "unpack", "load")),
    "command_dispatch": ("Command Dispatch", ("dispatch", "command", "handler", "opcode")),
}

CAPABILITY_BY_SUBSYSTEM = {
    "configuration": "Configuration Recovery",
    "network_c2": "C2 Communication",
    "persistence": "Persistence",
    "execution": "Command Execution",
    "injection": "Process Injection",
    "discovery": "System Discovery",
    "collection": "Collection",
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "crypto_encoding": "Crypto / Encoding",
    "file_operations": "File Operations",
    "registry_operations": "Registry Operations",
    "process_operations": "Process Operations",
    "service_operations": "Service Operations",
    "loader_initialization": "Loader / Initialization",
    "command_dispatch": "Command Dispatch",
}

