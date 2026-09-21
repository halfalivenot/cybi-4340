# cybi-4340

## Final honeypot dataset
| Field | Description |
|-------|-------------|
| ID | Unique primary key for each log entry
| session_id | Group events belonging to one interaction |
| timestamp | Date and time of the event |
| ip_addr | Source IPv4 address |
| src_port | Attacker's source port |
| dst_port | Port targeted on the honeypot |
| protocol | ICMP, TCP, or UDP |
| event_type | Interaction category |
| username | Attempted username |
| password | Attempted password |
| service | SSH, RDP, SMB, HTTP, etc |
| message | Raw metadata or system messages |

## Separate session-level table
| Field | Description |
|------|-------------|
| session_id | 
| ip_addr |
| session_start |
| session_end |
| event_count |
| ports_targeted |
| usernames_attempted |
| services_targeted | 

### Creating session id
```
WITH events AS (
    SELECT
        timestamp,
        ip_addr,
        event_id,
        username,
        message
    FROM `my-project.honeypot.normalized_events`
),

previous_events AS (
    SELECT
        *,
        LAG(timestamp) OVER (
            PARTITION BY ip_addr
            ORDER BY timestamp
        ) AS previous_timestamp
    FROM events
),

session_boundaries AS (
    SELECT
        *,
        CASE
            WHEN previous_timestamp IS NULL THEN 1

            WHEN TIMESTAMP_DIFF(
                timestamp,
                previous_timestamp,
                MINUTE
            ) > 30 THEN 1

            ELSE 0
        END AS new_session
    FROM previous_events
),

sessionized AS (
    SELECT
        *,
        SUM(new_session) OVER (
            PARTITION BY ip_addr
            ORDER BY timestamp
        ) AS session_number
    FROM session_boundaries
)

SELECT
    TO_HEX(
        SHA256(
            CONCAT(
                ip_addr,
                '-',
                CAST(session_number AS STRING)
            )
        )
    ) AS session_id,

    *
FROM sessionized;
```

Now create the honeypot dataset
```
SELECT
    session_id,

    ANY_VALUE(ip_addr) AS ip_addr,

    MIN(timestamp) AS session_start,

    MAX(timestamp) AS session_end,

    TIMESTAMP_DIFF(
        MAX(timestamp),
        MIN(timestamp),
        SECOND
    ) AS session_duration_seconds,

    COUNT(*) AS event_count,

    COUNTIF(event_type = 'LOGIN_FAILURE')
        AS failed_login_attempts,

    COUNTIF(event_type = 'LOGIN_SUCCESS')
        AS successful_logins,

    ARRAY_AGG(
        DISTINCT username IGNORE NULLS
    ) AS usernames_attempted,

    ARRAY_AGG(
        DISTINCT destination_port IGNORE NULLS
    ) AS ports_targeted,

    ARRAY_AGG(
        DISTINCT service IGNORE NULLS
    ) AS services_targeted

FROM `my-project.honeypot.sessionized_events`

GROUP BY session_id;

```

So final architecture
```
                 Windows VM
                     │
                     ▼
              Windows Event Logs
                     │
                     ▼
             Cloud Logging
                     │
                  Sink
                     │
                     ▼
             BigQuery RAW
                     │
                     ▼
          ┌────────────────────┐
          │ Normalize events   │
          │ Extract IP         │
          │ Extract ports      │
          │ Extract users      │
          │ Map event types    │
          └─────────┬──────────┘
                    │
                    ▼
            normalized_events
                    │
                    ▼
             Sessionization
                    │
                    ▼
           sessionized_events
                    │
                    ▼
            Session enrichment
                    │
                    ▼
             attacker_sessions
```
