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

## Explain this process  
```
Raw logs
   ↓
normalized_events
   ↓
sessionization
   ↓
sessionized_events
   ↓
session enrichment
   ↓
attacker_sessions
```
1. raw_logs - "What did Windows send me?"  
This is our source data. Essentially what our Windows VM generates these events.  
2. normalized_events - "Make every log look the same"  
This means taking different Windows formats and putting them into a consistent schema.Normalization = "Put the useful information into consistent columns"  
*Note: think about separting event_id and event_type or not. still need to figure that out if I do that  
3. sessionization - "Which events belong together?"  
Asking where does one attacker interaction begin and end?  
4. sessionzed_events - "Add the session id to each event?"  
sessionization = process of figuring out the sessions  
sessionized events = your events after attaching a session id to them  
Sessionizatio is the transformation; sessionzed_events is the resulting data  
5. session enrichment - "What can I calculate about this session?"  
6. attacker_sessions - "Store the final summary"  

Could do this  
```
raw_logs
    ↓
SQL query/view
    ↓
normalized_events
    ↓
SQL query
    ↓
sessionized_events
    ↓
SQL query
    ↓
attacker_sessions
```

Or this  
```
1. raw_logs
   ↓
2. normalized_events
   ↓
3. attacker_sessions

```
It would probably be easier to do the second thing. 
