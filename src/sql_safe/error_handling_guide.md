<!-- SPDX-License-Identifier: MIT
Copyright (c) 2024 MusicScope -->

# Error Handling Best Practices

## Professional Error Messages

### ✅ Good Error Messages
- **Specific**: "Invalid timeout value: got -5, expected positive number"
- **Actionable**: "Database connection failed. Check credentials and network connectivity"
- **Contextual**: "Query timeout after 30s on table 'users' (1M rows). Try increasing timeout_ms or optimizing query"

### ❌ Poor Error Messages
- **Vague**: "Something went wrong"
- **Technical only**: "NoneType object has no attribute 'execute'"
- **No guidance**: "Error occurred"

## Exception Handling Patterns

### Input Validation
```python
def process_data(data: Dict[str, Any], timeout: int = 30) -> Result:
    # Validate inputs with clear error messages
    if not isinstance(data, dict):
        raise ValidationError(
            "data", 
            data, 
            "dictionary",
            "Provide data as a dictionary with required fields"
        )
    
    if timeout <= 0:
        raise ValidationError(
            "timeout",
            timeout,
            "positive integer",
            "Set timeout to a positive number of seconds (e.g., 30)"
        )
```

### Resource Management
```python
def connect_to_database(url: str) -> Connection:
    try:
        return create_connection(url)
    except ConnectionError as e:
        raise DatabaseConnectionError(
            url,
            str(e),
            "Verify database URL format, credentials, and network access"
        )
```

### Operation Failures
```python
def scan_table(table_name: str) -> ScanResult:
    try:
        return perform_scan(table_name)
    except PermissionError:
        raise ScanError(
            table_name,
            "permission_check",
            "Insufficient database permissions",
            f"Grant SELECT permission on table '{table_name}'"
        )
    except TableNotFoundError:
        raise ScanError(
            table_name,
            "table_lookup",
            "Table does not exist",
            f"Verify table name '{table_name}' exists in the database"
        )
```

## Error Recovery Strategies

### Retry Logic
```python
def robust_operation(max_retries: int = 3) -> Result:
    for attempt in range(max_retries):
        try:
            return perform_operation()
        except TemporaryError as e:
            if attempt == max_retries - 1:
                raise OperationError(
                    "robust_operation",
                    f"Failed after {max_retries} attempts: {e}",
                    retry_possible=False,
                    "Check system resources and try again later"
                )
            time.sleep(2 ** attempt)  # Exponential backoff
```

### Graceful Degradation
```python
def enhanced_scan(table: str, use_ai: bool = True) -> ScanResult:
    try:
        if use_ai:
            return ai_enhanced_scan(table)
    except AIServiceError as e:
        logger.warning(f"AI service unavailable, falling back to basic scan: {e}")
    
    return basic_scan(table)
```
