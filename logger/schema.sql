-- schema.sql

-- Targets table - stores information about monitored assets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    address TEXT NOT NULL,
    category TEXT,  -- "web", "database", "iot", "server", etc.
    description TEXT,
    baseline_scan_id INTEGER,  -- Reference to the baseline scan
    active BOOLEAN DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (baseline_scan_id) REFERENCES scans(id)
);

-- Scans table - records each scan execution
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,  -- Now links to targets table
    target_address TEXT NOT NULL,  -- Keep for backward compatibility
    profile TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT DEFAULT 'completed',  -- 'completed', 'failed', 'partial'
    error_message TEXT,
    duration_seconds REAL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Hosts table - discovered hosts during scans
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Port events table - detailed port state information
CREATE TABLE IF NOT EXISTS port_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Port history table - tracks port state changes over time
CREATE TABLE IF NOT EXISTS port_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    seen_count INTEGER DEFAULT 1,
    current_state TEXT NOT NULL,
    UNIQUE(host, port, protocol)
);

-- Scan metadata - additional information about scan execution
CREATE TABLE IF NOT EXISTS scan_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_port_events_scan_host ON port_events(scan_id, host);
CREATE INDEX IF NOT EXISTS idx_port_events_state ON port_events(state);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_address);
CREATE INDEX IF NOT EXISTS idx_port_history_host_port ON port_history(host, port);