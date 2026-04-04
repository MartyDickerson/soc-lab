# 🗺️ Architecture Diagrams

These diagrams can be rendered on GitHub automatically using Mermaid syntax.

---

## Full SOC Lab Architecture

```mermaid
graph TB
    subgraph Endpoints["🖥️ Monitored Endpoints"]
        WS[Windows Server<br/>Wazuh Agent]
        LX[Linux Machines<br/>Wazuh Agent]
        DC[Docker Containers<br/>Docker Listener]
    end

    subgraph Wazuh["🛡️ Wazuh Server - Ubuntu"]
        WM[Wazuh Manager<br/>:55000]
        WI[Wazuh Indexer<br/>:9200]
        WD[Wazuh Dashboard<br/>:443]
        SA[SOC Automation<br/>Script]
        FW[Wazuh→Splunk<br/>Forwarder]
    end

    subgraph Splunk["📊 Splunk - Windows Server"]
        SP[Splunk Enterprise<br/>:8000]
        HEC[HTTP Event<br/>Collector :8088]
        DB[SOC Dashboard]
    end

    WS -->|agent logs| WM
    LX -->|agent logs| WM
    DC -->|docker events| WM
    WM -->|stores alerts| WI
    WI -->|visualizes| WD
    WI -->|queries| SA
    WM -->|alerts.json| FW
    FW -->|HTTP POST| HEC
    HEC -->|indexes| SP
    SP -->|displays| DB
```

---

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant E as Endpoint
    participant A as Wazuh Agent
    participant M as Wazuh Manager
    participant I as Wazuh Indexer
    participant F as Forwarder Script
    participant S as Splunk HEC
    participant D as Splunk Dashboard

    E->>A: System event occurs
    A->>M: Forward log/event
    M->>M: Match against 3000+ rules
    M->>I: Store alert
    M->>F: Write to alerts.json
    F->>S: HTTP POST alert
    S->>D: Index and display
    I->>D: Also visible in Wazuh Dashboard
```

---

## Alert Severity Flow

```mermaid
flowchart TD
    A[Alert Generated] --> B{Rule Level?}
    B -->|0-3| C[🔵 LOW<br/>Log only]
    B -->|4-7| D[🟡 MEDIUM<br/>Monitor]
    B -->|8-11| E[🟠 HIGH<br/>Investigate]
    B -->|12-15| F[🔴 CRITICAL<br/>Immediate action]

    D --> G{Enrichment}
    E --> G
    F --> G

    G -->|VT malicious > 5| H[🔴 Block IP]
    G -->|AbuseIPDB > 75| I[🟠 Consider block]
    G -->|MITRE tactic match| J[Apply tactic response]
    G -->|No hits| K[Standard response]
```

---

## Service Architecture

```mermaid
graph LR
    subgraph Boot["On System Boot"]
        WM[wazuh-manager.service]
        WI[wazuh-indexer.service]
        WD[wazuh-dashboard.service]
        DK[docker.service]
        WS[wazuh-splunk.service]
        CR[cron - hourly SOC script]
    end

    WM --> WI
    WM --> WD
    DK --> WM
    WM --> WS
    WM --> CR
```

---

## Network Ports

```mermaid
graph LR
    subgraph Wazuh["Wazuh Server"]
        P1[":1514 Agent comms"]
        P2[":1515 Agent enrollment"]
        P3[":55000 REST API"]
        P4[":9200 Indexer"]
        P5[":443 Dashboard"]
    end

    subgraph Splunk["Splunk Server"]
        P6[":8000 Web UI"]
        P7[":8088 HEC"]
        P8[":8089 Management"]
    end

    Agent -->|logs| P1
    Agent -->|enroll| P2
    Admin -->|API calls| P3
    Admin -->|queries| P4
    Admin -->|browser| P5
    Admin -->|browser| P6
    P1 -->|forward| P7
    Admin -->|manage| P8
```
