-- Unusual Query Patterns Detection in Snowflake
-- This query identifies users executing queries that deviate from their normal patterns
-- by analyzing time of day, query complexity, and tables accessed

WITH 
-- Calculate baseline metrics for each user over the past 30 days
user_baseline AS (
    SELECT 
        USER_NAME,
        -- Time of day patterns
        PERCENTILE_CONT(0.05) WITHIN GROUP (ORDER BY HOUR(CONVERT_TIMEZONE('UTC', 'America/Los_Angeles', START_TIME))) AS hour_p05,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY HOUR(CONVERT_TIMEZONE('UTC', 'America/Los_Angeles', START_TIME))) AS hour_p95,
        -- Query complexity patterns (using query length as a proxy)
        AVG(LENGTH(QUERY_TEXT)) AS avg_query_length,
        STDDEV(LENGTH(QUERY_TEXT)) AS stddev_query_length,
        -- Tables commonly accessed
        ARRAY_AGG(DISTINCT SPLIT_PART(SPLIT_PART(QUERY_TEXT, 'FROM ', 2), ' ', 1)) WITHIN GROUP (ORDER BY SPLIT_PART(SPLIT_PART(QUERY_TEXT, 'FROM ', 2), ' ', 1)) AS common_tables
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE 
        START_TIME >= DATEADD(DAY, -30, CURRENT_TIMESTAMP())
        AND QUERY_TYPE = 'SELECT'
        AND USER_NAME != 'SYSTEM'
        AND EXECUTION_STATUS = 'SUCCESS'
    GROUP BY 
        USER_NAME
    HAVING 
        COUNT(*) >= 20 -- Only establish baselines for users with sufficient activity
),

-- Get recent query activity (last 24 hours)
recent_activity AS (
    SELECT 
        QH.USER_NAME,
        QH.QUERY_ID,
        QH.START_TIME,
        QH.QUERY_TEXT,
        HOUR(CONVERT_TIMEZONE('UTC', 'America/Los_Angeles', QH.START_TIME)) AS query_hour,
        LENGTH(QH.QUERY_TEXT) AS query_length,
        SPLIT_PART(SPLIT_PART(QH.QUERY_TEXT, 'FROM ', 2), ' ', 1) AS table_accessed,
        QH.BYTES_SCANNED,
        QH.EXECUTION_TIME,
        QH.WAREHOUSE_NAME
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY QH
    WHERE 
        QH.START_TIME >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP())
        AND QH.QUERY_TYPE = 'SELECT'
        AND QH.USER_NAME != 'SYSTEM'
        AND QH.EXECUTION_STATUS = 'SUCCESS'
)

-- Identify anomalous activity
SELECT 
    RA.USER_NAME,
    RA.QUERY_ID,
    RA.START_TIME,
    RA.QUERY_TEXT,
    'Unusual query hour' AS anomaly_type,
    'Query executed at hour ' || RA.query_hour || ' outside normal hours (' || UB.hour_p05 || ' to ' || UB.hour_p95 || ')' AS anomaly_details
FROM 
    recent_activity RA
JOIN 
    user_baseline UB ON RA.USER_NAME = UB.USER_NAME
WHERE 
    RA.query_hour < UB.hour_p05 OR RA.query_hour > UB.hour_p95

UNION ALL

SELECT 
    RA.USER_NAME,
    RA.QUERY_ID,
    RA.START_TIME,
    RA.QUERY_TEXT,
    'Unusual query complexity' AS anomaly_type,
    'Query length (' || RA.query_length || ') deviates from normal pattern (avg: ' || UB.avg_query_length || ', stddev: ' || UB.stddev_query_length || ')' AS anomaly_details
FROM 
    recent_activity RA
JOIN 
    user_baseline UB ON RA.USER_NAME = UB.USER_NAME
WHERE 
    ABS(RA.query_length - UB.avg_query_length) > 3 * UB.stddev_query_length  -- More than 3 standard deviations

UNION ALL

SELECT 
    RA.USER_NAME,
    RA.QUERY_ID,
    RA.START_TIME,
    RA.QUERY_TEXT,
    'Unusual table access' AS anomaly_type,
    'Accessed table ' || RA.table_accessed || ' which is not in commonly accessed tables' AS anomaly_details
FROM 
    recent_activity RA
JOIN 
    user_baseline UB ON RA.USER_NAME = UB.USER_NAME
WHERE 
    RA.table_accessed IS NOT NULL
    AND RA.table_accessed != ''
    AND NOT ARRAY_CONTAINS(RA.table_accessed::VARIANT, UB.common_tables)
    
ORDER BY 
    USER_NAME, START_TIME DESC;
