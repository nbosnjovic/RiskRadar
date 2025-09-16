-- systems: whitelist skeniranih sajtova
CREATE TABLE IF NOT EXISTS systems (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       VARCHAR(120) NOT NULL,
  url        VARCHAR(512) NOT NULL,
  note       TEXT,                        
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- svaki run skeniranja
CREATE TABLE IF NOT EXISTS scan_runs (
  id            INTEGER PRIMARY KEY,
  system_id     INTEGER NOT NULL REFERENCES systems(id),
  mode          TEXT NOT NULL,                  -- QUICK / FULL
  started_at    TEXT DEFAULT CURRENT_TIMESTAMP,
  duration_s    REAL,
  high_count    INTEGER, 
  med_count     INTEGER, 
  low_count     INTEGER,
  max_rr        INTEGER,                        -- 1–25
  max_rr_bucket TEXT,                           -- pri/zad/tol/nep
  pdf_path      TEXT,                           
  UNIQUE(system_id, started_at)
);

-- nalazi iz jednog run-a
CREATE TABLE IF NOT EXISTS findings (
  id             INTEGER PRIMARY KEY,
  scan_id        INTEGER NOT NULL REFERENCES scan_runs(id),
  alert          TEXT NOT NULL,
  cwe_id         INTEGER,
  risk           TEXT NOT NULL,                 -- HIGH/MEDIUM/LOW
  rr_likelihood  INTEGER,
  rr_impact      INTEGER,
  rr_score       INTEGER,
  rr_bucket      TEXT,
  instances      INTEGER,
  sample_urls    TEXT,                         
  param          TEXT,
  evidence       TEXT,
  fix            TEXT,
  reference      TEXT,
  signature      TEXT NOT NULL                
);

-- tretman nalaza (po sistemu)
CREATE TABLE IF NOT EXISTS finding_status (
  id          INTEGER PRIMARY KEY,
  system_id   INTEGER NOT NULL REFERENCES systems(id),
  signature   TEXT NOT NULL,                    
  status      TEXT NOT NULL,                    -- OPEN/ACCEPTED/FP/FIXED
  note        TEXT,
  updated_at  TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(system_id, signature)
);
