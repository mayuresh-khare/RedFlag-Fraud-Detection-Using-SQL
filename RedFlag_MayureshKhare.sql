-- =====================================================================
-- RedFlag — Fraud Detection Submission
-- Student: Mayuresh Khare
-- Batch: DA-DS-1
-- =====================================================================

USE redflag;

-- =====================================================================
-- PATTERN 1 · VELOCITY FRAUD
-- What I'm looking for:
-- Detect users performing 30 or more transactions on a single day.
-- =====================================================================
SELECT user_id, DATE(txn_time) AS transaction_date, COUNT(*) AS transactions_per_day
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY transactions_per_day DESC, user_id;
-- Findings:
-- 50 suspicious user-day combinations identified.

-- =====================================================================
-- PATTERN 2 · ROUND-AMOUNT CLUSTERING
-- What I'm looking for:
-- Detect users making repeated suspicious round-value transactions.
-- =====================================================================
SELECT user_id, COUNT(*) AS round_transactions_made
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_transactions_made DESC, user_id;
-- Findings:
-- 25 suspicious users identified.

-- =============================================================================
-- PATTERN 3 · CARD TESTING
-- What I'm looking for:
-- Detect users performing 30 or more very small-value transactions
-- (less than ₹10) on the same day.
-- Fraudsters often perform these transactions to verify whether stolen
-- cards are active before attempting larger purchases.
-- Expected suspects: 20
-- =============================================================================
SELECT user_id, DATE(txn_time), COUNT(*) AS small_transactions_made
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_transactions_made DESC, user_id;
-- Findings:
-- 20 suspicious user-day combinations were identified.
-- The detected users exhibited concentrated low-value transaction activity,
-- consistent with card-testing behaviour.

-- =============================================================================
-- PATTERN 4 · FAILED-THEN-SUCCEEDED (SIMPLIFIED)
-- What I'm looking for:
-- Detect users with 20 or more failed transactions. A high number of
-- failed payment attempts may indicate automated card testing,
-- credential stuffing, or repeated fraud attempts.
-- Expected suspects: 25
-- =============================================================================
SELECT user_id, COUNT(*) AS failed_transactions
FROM transactions
WHERE status = 'FAILED'
GROUP BY user_id
HAVING COUNT(*) >= 20
ORDER BY failed_transactions DESC, user_id;
-- Findings:
-- 25 suspicious users were identified.
-- These users generated an unusually high number of failed transactions,
-- matching the expected failed-payment fraud pattern.

-- =============================================================================
-- PATTERN 5 · ODD-HOUR CONCENTRATION
-- What I'm looking for:
-- Detect users with at least 30 total transactions where 80% or more of
-- their activity occurs between 2:00 AM and 4:59 AM. Such behaviour is
-- commonly associated with automated fraud scripts.
-- Expected suspects: 20
-- =============================================================================
SELECT user_id, 
	   COUNT(*) AS total_transactions,
	   SUM(CASE 
			WHEN HOUR(txn_time) 
			BETWEEN 2 AND 4 
			THEN 1 
			ELSE 0 
		END) AS odd_transactions
FROM transactions
GROUP BY user_id
HAVING
    COUNT(*) >= 30
    AND SUM(CASE
				WHEN HOUR(txn_time) BETWEEN 2 AND 4
				THEN 1
				ELSE 0
			END) * 1.0 / COUNT(*) >= 0.80
ORDER BY total_transactions DESC, user_id;
-- Findings:
-- 20 suspicious users were identified.
-- More than 80% of their activity occurred during odd hours,
-- indicating potential automated or bot-driven transactions.

-- =============================================================================
-- PATTERN 6 · MULE ACCOUNTS (SIMPLIFIED)
-- What I'm looking for:
-- Detect users performing 8 or more CREDIT transactions.
-- Accounts receiving unusually frequent credits may indicate mule
-- accounts used for laundering stolen funds.
-- Expected suspects: 30
-- =============================================================================
SELECT user_id, COUNT(*) AS credit_transactions
FROM transactions
WHERE txn_type = 'CREDIT'
GROUP BY user_id
HAVING COUNT(*) >= 8
ORDER BY credit_transactions DESC, user_id;
-- Findings:
-- 30 suspicious users were identified.
-- These users received an unusually large number of CREDIT transactions,
-- matching the simplified mule-account detection pattern.

-- =============================================================================
-- PATTERN 7 · REFUND ABUSE
-- What I'm looking for:
-- Detect users with at least 20 total transactions where more than 40%
-- of their transactions are REFUND transactions. A high refund ratio
-- may indicate refund fraud or chargeback abuse.
-- Expected suspects: 24–25
-- =============================================================================
SELECT user_id, 
	   COUNT(*) AS total_transactions,
       SUM(CASE
	           WHEN txn_type = 'REFUND'
               THEN 1
               ELSE 0
		    END) AS refund_transactions
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
	   AND SUM(CASE
	           WHEN txn_type = 'REFUND'
               THEN 1
               ELSE 0
		    END) * 1.0 / COUNT(*) > 0.40
ORDER BY total_transactions DESC, user_id;
-- Findings:
-- 24 suspicious users were identified.
-- These users exhibited an unusually high refund ratio, indicating
-- possible refund abuse or chargeback fraud.

-- =============================================================================
-- PATTERN 8 · MERCHANT COLLUSION
-- What I'm looking for:
-- Detect merchants where the Top 5 users contribute more than 60% of
-- the merchant's total transaction value. Such concentration may indicate
-- merchant collusion or money laundering activity.
-- Expected suspects: 15
-- =============================================================================
WITH user_totals AS
(
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS total_amount
    FROM transactions
    GROUP BY
        merchant_id,
        user_id
),

ranked_users AS
(
    SELECT
        merchant_id,
        user_id,
        total_amount,
        ROW_NUMBER() OVER
        (
            PARTITION BY merchant_id
            ORDER BY total_amount DESC
        ) AS user_rank
    FROM user_totals
),

top5_totals AS
(
    SELECT
        merchant_id,
        SUM(total_amount) AS top5_amount
    FROM ranked_users
    WHERE user_rank <= 5
    GROUP BY merchant_id
),

merchant_totals AS
(
    SELECT
        merchant_id,
        SUM(amount) AS merchant_total
    FROM transactions
    GROUP BY merchant_id
)

SELECT
    mt.merchant_id,
    mt.merchant_total,
    t5.top5_amount,
    ROUND((t5.top5_amount * 1.0 / mt.merchant_total) * 100, 2) AS top5_percentage
FROM merchant_totals mt
JOIN top5_totals t5
    ON mt.merchant_id = t5.merchant_id
WHERE
    (t5.top5_amount * 1.0 / mt.merchant_total) > 0.60
ORDER BY
    mt.merchant_id;
-- Findings:
-- 15 suspicious merchants were identified.
-- The Top 5 customers contributed more than 60% of total transaction
-- value, matching the merchant collusion fraud pattern.

-- =============================================================================
-- PATTERN 9 · JUST-UNDER-THRESHOLD (STRUCTURING)
-- What I'm looking for:
-- Detect users performing 10 or more transactions of exactly ₹9,999.00.
-- Such behaviour is commonly associated with transaction structuring
-- (smurfing) to avoid regulatory reporting thresholds.
-- Expected suspects: 20
-- =============================================================================
SELECT user_id, COUNT(*) AS suspicious_transactions
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY suspicious_transactions DESC, user_id;
-- Findings:
-- 20 suspicious users were identified.
-- These users repeatedly performed transactions at exactly ₹9,999.00,
-- matching the classic structuring (smurfing) fraud pattern.

-- =============================================================================
-- PATTERN 10 · DORMANT-THEN-ACTIVE
-- What I'm looking for:
-- Detect users who remained inactive for 90 or more days and then
-- suddenly became active with at least 15 transactions. Such behaviour
-- is commonly associated with account takeover or compromised accounts.
-- Expected suspects: 25–27
-- =============================================================================
WITH transaction_history AS
(
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER
        (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn
    FROM transactions
),

gaps AS
(
    SELECT
        user_id,
        txn_time,
        previous_txn,
        DATEDIFF(txn_time, previous_txn) AS gap_days
    FROM transaction_history
    WHERE previous_txn IS NOT NULL
),

post_gap_activity AS
(
    SELECT
        g.user_id,
        g.txn_time AS restart_transaction,
        COUNT(t.txn_id) AS post_gap_transactions
    FROM gaps g
    JOIN transactions t
        ON g.user_id = t.user_id
       AND t.txn_time >= g.txn_time
    WHERE g.gap_days >= 90
    GROUP BY
        g.user_id,
        g.txn_time
)

SELECT
    user_id,
    restart_transaction,
    post_gap_transactions
FROM post_gap_activity
WHERE
    post_gap_transactions >= 15
ORDER BY
    post_gap_transactions DESC,
    user_id;
-- Findings:
-- 26 suspicious users were identified.
-- These users resumed activity after remaining inactive for at least
-- 90 days and subsequently generated a high volume of transactions,
-- indicating potential account takeover.

-- =============================================================================
-- PATTERN 11 · VELOCITY SPIKE
-- What I'm looking for:
-- Detect users whose peak monthly transaction count is at least five
-- times their average monthly transaction count, with a peak of at
-- least 20 transactions. Such sudden spikes may indicate abnormal
-- behaviour or account compromise.
-- Expected suspects: 35–45
-- =============================================================================

WITH monthly_transactions AS
(
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS transaction_month,
        COUNT(*) AS monthly_transaction_count
    FROM transactions
    GROUP BY
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m')
),

user_statistics AS
(
    SELECT
        user_id,
        AVG(monthly_transaction_count) AS average_monthly_transactions,
        MAX(monthly_transaction_count) AS peak_monthly_transactions
    FROM monthly_transactions
    GROUP BY user_id
)

SELECT
    user_id,
    ROUND(average_monthly_transactions, 2) AS average_monthly_transactions,
    peak_monthly_transactions,
    ROUND(peak_monthly_transactions / average_monthly_transactions, 2) AS spike_ratio
FROM user_statistics
WHERE
    peak_monthly_transactions >= 20
    AND (peak_monthly_transactions / average_monthly_transactions) >= 5
ORDER BY
    spike_ratio DESC,
    user_id;
-- Findings:
-- 3 users were identified based on the implemented fraud detection logic.
-- These users exhibited monthly transaction spikes exceeding five times
-- their average monthly activity with a peak of at least 20 transactions.
-- we've verified multiple interpretations and none reproduce the published expectation,
-- the discrepancy appears to come from the project specification rather than from SQL.

-- =============================================================================
-- PATTERN 12 · GEOGRAPHIC IMPOSSIBILITY
-- What I'm looking for:
-- Detect users performing consecutive transactions from different cities
-- within 60 minutes. Such behaviour is physically impossible and may
-- indicate account takeover or stolen-card usage.
-- Expected suspects: 15
-- =============================================================================
WITH transaction_history AS
(
    SELECT
        user_id,
        city,
        txn_time,
        LAG(city) OVER
        (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_city,

        LAG(txn_time) OVER
        (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_time
    FROM transactions
)

SELECT DISTINCT
    user_id
FROM transaction_history
WHERE
    previous_city IS NOT NULL
    AND city <> previous_city
    AND TIMESTAMPDIFF(MINUTE, previous_time, txn_time) <= 60
ORDER BY user_id;
-- Findings:
-- 80 users were identified with geographically impossible transaction
-- patterns based on the implemented detection logic. Each flagged user
-- performed consecutive transactions from different cities within
-- 60 minutes, indicating potential account compromise.