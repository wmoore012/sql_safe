<!-- SPDX-License-Identifier: MIT
Copyright (c) 2024 MusicScope -->

# Professional Docstring Templates

## Function Docstrings

### Template
```python
def function_name(
    param1: Type1,
    param2: Type2 = default_value,
    *args: Any,
    **kwargs: Any
) -> ReturnType:
    """
    Brief one-line description of what the function does.
    
    Longer description explaining the function's purpose, behavior,
    and any important implementation details. Include performance
    characteristics and limitations if relevant.
    
    Args:
        param1: Description of the first parameter, including
            expected format, constraints, and examples
        param2: Description with default value explanation.
            Defaults to default_value.
        *args: Additional positional arguments description
        **kwargs: Additional keyword arguments description
    
    Returns:
        Description of return value, including type information
        and what the value represents
    
    Raises:
        SpecificError: When this specific error condition occurs
        AnotherError: When this other condition happens
    
    Example:
        Basic usage example:
        
        >>> result = function_name("example", param2=42)
        >>> print(result)
        ExpectedOutput
        
        Advanced usage with error handling:
        
        >>> try:
        ...     result = function_name("invalid")
        ... except ValidationError as e:
        ...     print(f"Validation failed: {e}")
    
    Note:
        Any important notes about usage, performance, or limitations.
        
    See Also:
        related_function: Related functionality
        SomeClass: Related class
    """
```

### Real Examples

#### Data Processing Function
```python
def scan_nulls(
    database_url: str,
    table_patterns: Optional[List[str]] = None,
    severity_threshold: str = "warning"
) -> List[QualityIssue]:
    """
    Scan database tables for null value quality issues.
    
    Performs comprehensive null value analysis across specified tables,
    identifying columns with unexpected null patterns and calculating
    null percentages for data quality assessment.
    
    Args:
        database_url: SQLAlchemy-compatible database connection string.
            Format: "mysql://user:pass@host:port/database"
        table_patterns: List of table name patterns to scan. Supports
            SQL LIKE patterns with % wildcards. If None, scans all tables.
            Example: ["users%", "orders", "product_*"]
        severity_threshold: Minimum severity level to report. One of:
            "info", "warning", "error", "critical". Defaults to "warning".
    
    Returns:
        List of QualityIssue objects containing:
        - table_name: Name of the table with issues
        - column_name: Column containing null values
        - issue_type: Type of quality issue detected
        - severity: Issue severity level
        - null_percentage: Percentage of null values (0.0-100.0)
        - suggestion: Recommended action to resolve the issue
    
    Raises:
        DatabaseConnectionError: When database connection fails
        ValidationError: When parameters are invalid
        ScanError: When table scanning encounters errors
    
    Example:
        Basic null scanning:
        
        >>> issues = scan_nulls("mysql://user:pass@localhost/mydb")
        >>> for issue in issues:
        ...     print(f"{issue.table_name}.{issue.column_name}: {issue.null_percentage}% nulls")
        users.email: 15.2% nulls
        orders.shipping_address: 8.7% nulls
        
        Targeted scanning with patterns:
        
        >>> issues = scan_nulls(
        ...     "mysql://user:pass@localhost/mydb",
        ...     table_patterns=["user%", "order%"],
        ...     severity_threshold="error"
        ... )
        >>> critical_issues = [i for i in issues if i.severity == "critical"]
        
        Error handling:
        
        >>> try:
        ...     issues = scan_nulls("invalid://connection")
        ... except DatabaseConnectionError as e:
        ...     print(f"Connection failed: {e.suggestion}")
    
    Note:
        Performance scales linearly with table size. For tables with >1M rows,
        consider using table_patterns to limit scope or run during off-peak hours.
        
        Memory usage is approximately 1MB per 100K rows scanned.
    
    See Also:
        health_check: Comprehensive database quality assessment
        scan_orphans: Detect orphaned records and referential integrity issues
    """
```

## Class Docstrings

### Template
```python
class ClassName:
    """
    Brief description of the class purpose.
    
    Detailed description of what the class represents, its main
    responsibilities, and how it fits into the larger system.
    
    Attributes:
        attribute1: Description of public attribute
        attribute2: Description with type information
    
    Example:
        Basic usage:
        
        >>> obj = ClassName(param="value")
        >>> result = obj.method()
        >>> print(result)
        
        Advanced usage:
        
        >>> with ClassName(param="value") as obj:
        ...     obj.configure(setting=True)
        ...     results = obj.batch_process(data)
    """
```

## Module Docstrings

### Template
```python
"""
Module name and brief description.

This module provides [main functionality] for [target use case].
It includes [key components] and supports [main features].

Key Features:
    • Feature 1: Description
    • Feature 2: Description
    • Feature 3: Description

Performance Characteristics:
    • Throughput: X operations/second
    • Memory usage: Y MB per Z operations
    • Scalability: Handles up to N concurrent operations

Example:
    Quick start example:
    
    >>> from module_name import main_function
    >>> result = main_function("input")
    >>> print(result)

Author: Your Name
Version: 1.0.0
"""
```
