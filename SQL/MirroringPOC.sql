/* ============================================================================
   Fabric Mirroring - Azure SQL Database READINESS ASSESSMENT
   ----------------------------------------------------------------------------
   Purpose : Scan a source database and report every mirroring limitation:
             table-level blocks, column drops, precision/size trims, and an
             overall per-table verdict (BLOCKED / COLUMN LOSS / TRIM / OK).
   Run on  : The source Azure SQL Database you intend to mirror (read-only).
   Based on: Microsoft "Limitations - Fabric mirrored databases from Azure SQL".
   Sections:
     1. Database-level gate checks (CDC / Synapse Link / durability / table count)
     2. Table-level feature blocks (temporal/graph/in-memory/columnstore/external/ledger)
     3. Column-level issues (unsupported types, computed, json/vector, precision-7)
     4. Primary-key blocks (unsupported / precision-7 column in the PK)
     5. LOB size risk (>1MB truncation) - generates per-column checks
     6. OVERALL VERDICT per table
   ============================================================================ */

SET NOCOUNT ON;

/* ----------------------------------------------------------------------------
   1. DATABASE-LEVEL GATE CHECKS
   ---------------------------------------------------------------------------- */
PRINT '=== 1. Database-level checks ===';

SELECT
    DB_NAME() AS DatabaseName,
    (SELECT is_cdc_enabled FROM sys.databases WHERE database_id = DB_ID())              AS CDC_Enabled_MUST_BE_0,
    (SELECT COUNT(*) FROM sys.tables WHERE is_ms_shipped = 0)                            AS UserTableCount_MAX_1000,
    CASE WHEN (SELECT COUNT(*) FROM sys.tables WHERE is_ms_shipped = 0) > 1000
         THEN 'OVER 1000 TABLE LIMIT' ELSE 'OK' END                                     AS TableCountVerdict;
-- Note: delayed durability + Synapse Link + already-mirrored can't be read reliably here;
-- verify manually: ALTER DATABASE ... (delayed durability), and Fabric workspace usage.

/* ----------------------------------------------------------------------------
   2. TABLE-LEVEL FEATURE BLOCKS  (any row here = whole table BLOCKED)
   ---------------------------------------------------------------------------- */
PRINT '=== 2. Table-level feature blocks ===';

-- is_ledger only exists on engines with ledger table support; build the check dynamically so older engines don't error
DECLARE @HasLedgerCol bit = CASE WHEN COL_LENGTH('sys.tables', 'is_ledger') IS NOT NULL THEN 1 ELSE 0 END;
DECLARE @Sql2 nvarchar(max) = N'
SELECT s.name AS SchemaName, t.name AS TableName,
    CONCAT_WS('', '',
        CASE WHEN t.temporal_type <> 0      THEN ''Temporal''     END,
        CASE WHEN t.is_memory_optimized = 1 THEN ''In-Memory''    END,
        CASE WHEN t.is_external = 1         THEN ''External''      END,
        CASE WHEN t.is_node = 1             THEN ''Graph-Node''    END,
        CASE WHEN t.is_edge = 1             THEN ''Graph-Edge''    END,'
    + CASE WHEN @HasLedgerCol = 1 THEN N' CASE WHEN t.is_ledger = 1 THEN ''Ledger'' END,' ELSE N'' END
    + N'
        CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id=t.object_id AND i.type_desc LIKE ''%COLUMNSTORE%'')
             THEN ''Columnstore'' END,
        CASE WHEN EXISTS (SELECT 1 FROM sys.columns c WHERE c.object_id=t.object_id AND c.column_encryption_key_id IS NOT NULL)
             THEN ''Always-Encrypted'' END
    ) AS BlockingFeature
FROM sys.tables t
JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE t.is_ms_shipped = 0
  AND ( t.temporal_type <> 0 OR t.is_memory_optimized = 1 OR t.is_external = 1
     OR t.is_node = 1 OR t.is_edge = 1'
    + CASE WHEN @HasLedgerCol = 1 THEN N' OR t.is_ledger = 1' ELSE N'' END
    + N'
     OR EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id=t.object_id AND i.type_desc LIKE ''%COLUMNSTORE%'')
     OR EXISTS (SELECT 1 FROM sys.columns c WHERE c.object_id=t.object_id AND c.column_encryption_key_id IS NOT NULL) )
ORDER BY t.name;';
EXEC sp_executesql @Sql2;

/* ----------------------------------------------------------------------------
   3. COLUMN-LEVEL ISSUES  (dropped columns / json-vector / precision-7)
   ---------------------------------------------------------------------------- */
PRINT '=== 3. Column-level issues ===';

SELECT
    s.name AS SchemaName, t.name AS TableName, c.name AS ColumnName,
    ty.name + CASE WHEN ty.name IN ('datetime2','datetimeoffset','time')
                   THEN '(' + CAST(c.scale AS varchar) + ')' ELSE '' END AS DataType,
    CASE
        WHEN c.is_computed = 1 THEN 'DROP (computed)'
        WHEN ty.name IN ('json','vector') THEN 'DROP column (json/vector)'
        WHEN ty.name IN ('image','text','ntext','xml','timestamp','rowversion','sql_variant','geometry','geography','hierarchyid') THEN 'DROP (unsupported type)'
        WHEN ty.is_user_defined = 1 THEN 'DROP (UDT)'
        WHEN ty.name IN ('datetime2','datetimeoffset','time') AND c.scale = 7 THEN 'TRIM (7-digit precision)'
    END AS Impact,
    CASE WHEN pk.column_id IS NOT NULL THEN 'YES -> BLOCKS TABLE' ELSE '' END AS InPrimaryKey
FROM sys.columns c
JOIN sys.tables  t ON c.object_id = t.object_id
JOIN sys.schemas s ON t.schema_id = s.schema_id
JOIN sys.types  ty ON c.user_type_id = ty.user_type_id
LEFT JOIN (
    SELECT ic.object_id, ic.column_id
    FROM sys.index_columns ic
    JOIN sys.indexes i ON ic.object_id = i.object_id AND ic.index_id = i.index_id
    WHERE i.is_primary_key = 1
) pk ON pk.object_id = c.object_id AND pk.column_id = c.column_id
WHERE t.is_ms_shipped = 0
  AND ( c.is_computed = 1 OR ty.is_user_defined = 1
     OR ty.name IN ('json','vector','image','text','ntext','xml','timestamp','rowversion','sql_variant','geometry','geography','hierarchyid')
     OR (ty.name IN ('datetime2','datetimeoffset','time') AND c.scale = 7) )
ORDER BY InPrimaryKey DESC, t.name, c.column_id;

/* ----------------------------------------------------------------------------
   4. PRIMARY-KEY BLOCKS  (unsupported / precision-7 column used in the PK)
      Any row here = table is FULLY BLOCKED from mirroring.
   ---------------------------------------------------------------------------- */
PRINT '=== 4. Primary-key blocks (table-level) ===';

SELECT s.name AS SchemaName, t.name AS TableName, c.name AS PKColumn,
       ty.name + CASE WHEN ty.name IN ('datetime2','datetimeoffset','time')
                      THEN '(' + CAST(c.scale AS varchar) + ')' ELSE '' END AS DataType,
       'BLOCKED - unsupported type in PK' AS Verdict
FROM sys.index_columns ic
JOIN sys.indexes i ON ic.object_id = i.object_id AND ic.index_id = i.index_id AND i.is_primary_key = 1
JOIN sys.columns c ON ic.object_id = c.object_id AND ic.column_id = c.column_id
JOIN sys.tables  t ON c.object_id = t.object_id
JOIN sys.schemas s ON t.schema_id = s.schema_id
JOIN sys.types  ty ON c.user_type_id = ty.user_type_id
WHERE t.is_ms_shipped = 0
  AND ( c.is_computed = 1 OR ty.is_user_defined = 1
     OR ty.name IN ('geometry','geography','hierarchyid','sql_variant','timestamp','rowversion')
     OR (ty.name IN ('datetime2','datetimeoffset','time') AND c.scale = 7) )
ORDER BY t.name;

/* ----------------------------------------------------------------------------
   5. LOB SIZE RISK (>1MB truncation)
      Metadata can't show actual sizes - this generates the checks to run.
   ---------------------------------------------------------------------------- */
PRINT '=== 5. LOB size checks (copy output below and run) ===';

SELECT 'SELECT ''' + s.name + '.' + t.name + '.' + c.name
     + ''' AS Col, MAX(DATALENGTH(' + QUOTENAME(c.name) + ')) AS MaxBytes, '
     + '1048576 AS LimitBytes FROM ' + QUOTENAME(s.name) + '.' + QUOTENAME(t.name) + ';' AS CheckSql
FROM sys.columns c
JOIN sys.tables  t ON c.object_id = t.object_id
JOIN sys.schemas s ON t.schema_id = s.schema_id
JOIN sys.types  ty ON c.user_type_id = ty.user_type_id
WHERE t.is_ms_shipped = 0
  AND ( (ty.name IN ('varchar','nvarchar','varbinary') AND c.max_length = -1)
        OR ty.name IN ('image','text','ntext') );

/* ----------------------------------------------------------------------------
   6. OVERALL VERDICT PER TABLE
      BLOCKED       = table feature or unsupported PK -> will NOT mirror
      COLUMN LOSS   = mirrors, but some columns dropped
      TRIM          = mirrors, but precision/size loss
      OK            = mirrors cleanly
   ---------------------------------------------------------------------------- */
PRINT '=== 6. Overall verdict per table ===';

-- built as dynamic SQL so the is_ledger predicate is omitted entirely on engines without that column
DECLARE @Sql6 nvarchar(max) = N'
;WITH tbl AS (
    SELECT t.object_id, s.name AS SchemaName, t.name AS TableName
    FROM sys.tables t JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE t.is_ms_shipped = 0
),
feat AS (  -- table-level blocks
    SELECT object_id FROM sys.tables
    WHERE is_ms_shipped = 0
      AND ( temporal_type <> 0 OR is_memory_optimized = 1 OR is_external = 1
         OR is_node = 1 OR is_edge = 1'
    + CASE WHEN @HasLedgerCol = 1 THEN N' OR is_ledger = 1' ELSE N'' END
    + N'
         OR EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id=sys.tables.object_id AND i.type_desc LIKE ''%COLUMNSTORE%'')
         OR EXISTS (SELECT 1 FROM sys.columns c WHERE c.object_id=sys.tables.object_id AND c.column_encryption_key_id IS NOT NULL) )
),
pkblock AS (  -- unsupported column in PK
    SELECT DISTINCT c.object_id
    FROM sys.index_columns ic
    JOIN sys.indexes i ON ic.object_id=i.object_id AND ic.index_id=i.index_id AND i.is_primary_key=1
    JOIN sys.columns c ON ic.object_id=c.object_id AND ic.column_id=c.column_id
    JOIN sys.types ty ON c.user_type_id=ty.user_type_id
    WHERE c.is_computed=1 OR ty.is_user_defined=1
       OR ty.name IN (''geometry'',''geography'',''hierarchyid'',''sql_variant'',''timestamp'',''rowversion'')
       OR (ty.name IN (''datetime2'',''datetimeoffset'',''time'') AND c.scale=7)
),
coldrop AS (  -- columns that get dropped
    SELECT DISTINCT c.object_id
    FROM sys.columns c JOIN sys.types ty ON c.user_type_id=ty.user_type_id
    WHERE c.is_computed=1 OR ty.is_user_defined=1
       OR ty.name IN (''json'',''vector'',''image'',''text'',''ntext'',''xml'',''timestamp'',''rowversion'',''sql_variant'',''geometry'',''geography'',''hierarchyid'')
),
trim AS (  -- precision-7 (non-PK) columns
    SELECT DISTINCT c.object_id
    FROM sys.columns c JOIN sys.types ty ON c.user_type_id=ty.user_type_id
    WHERE ty.name IN (''datetime2'',''datetimeoffset'',''time'') AND c.scale=7
)
SELECT tbl.SchemaName, tbl.TableName,
    CASE
        WHEN feat.object_id IS NOT NULL OR pkblock.object_id IS NOT NULL THEN ''BLOCKED - will NOT mirror''
        WHEN coldrop.object_id IS NOT NULL THEN ''COLUMN LOSS - mirrors, some columns dropped''
        WHEN trim.object_id IS NOT NULL THEN ''TRIM - mirrors, precision/size loss''
        ELSE ''OK - mirrors cleanly''
    END AS OverallVerdict
FROM tbl
LEFT JOIN feat    ON feat.object_id    = tbl.object_id
LEFT JOIN pkblock ON pkblock.object_id = tbl.object_id
LEFT JOIN coldrop ON coldrop.object_id = tbl.object_id
LEFT JOIN trim    ON trim.object_id    = tbl.object_id
ORDER BY
    CASE
        WHEN feat.object_id IS NOT NULL OR pkblock.object_id IS NOT NULL THEN 1
        WHEN coldrop.object_id IS NOT NULL THEN 2
        WHEN trim.object_id IS NOT NULL THEN 3
        ELSE 4
    END, tbl.TableName;';
EXEC sp_executesql @Sql6;
