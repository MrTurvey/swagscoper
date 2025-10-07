# swagscoper

## Overview

`swagscoper` is designed to facilitate the security assessment scoping process using Swagger/OpenAPI documented APIs. It analyzes API specifications to provide method counts and parameter analysis for security assessment planning.

## Features

- **HTTP Method Analysis** - Count and categorize all HTTP methods (GET, POST, PUT, DELETE, etc.)
- **Method Filtering** - Filter results to show only specific HTTP methods
- **Parameter Counting** - Analyze parameters per endpoint including required vs optional
- **CSV Export** - Save results to CSV files for reporting and further analysis
- **Authentication Support** - Bearer tokens, API keys, and Basic authentication
- **Local & Remote** - Analyze both local JSON files and remote URLs
- **Auto-detection** - Automatically finds JSON endpoints from swagger-ui.html URLs
- **OpenAPI Support** - Works with both Swagger 2.0 and OpenAPI 3.0 specifications

## Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/MrTurvey/swagscoper.git
cd swagscoper
pip install -r requirements.txt
```

## Usage

### Basic Analysis

Analyze a remote API:
```bash
python3 swagscoper.py -t https://api.example.com/v2/api-docs
```

Analyze a local file:
```bash
python3 swagscoper.py -t input.json
```

### With Authentication

Bearer token:
```bash
python3 swagscoper.py -t https://api.example.com/swagger.json --auth-bearer YOUR_TOKEN
```

API key header:
```bash
python3 swagscoper.py -t https://api.example.com/api-docs --auth-header "X-API-Key: YOUR_KEY"
```

Basic authentication:
```bash
python3 swagscoper.py -t https://api.example.com/api-docs --auth-basic username:password
```

### Parameter Analysis

Show parameter counts per endpoint:
```bash
python3 swagscoper.py -t input.json --params
```

### Filtering Methods

Filter to show only specific HTTP methods:
```bash
python3 swagscoper.py -t input.json --methods GET,POST
```

### CSV Export

Export summary to CSV:
```bash
python3 swagscoper.py -t input.json -o output.csv
```

Export detailed endpoint data with parameters:
```bash
python3 swagscoper.py -t input.json --params -o endpoints.csv
```

Export filtered results:
```bash
python3 swagscoper.py -t input.json --methods DELETE --params -o delete_endpoints.csv
```

## Example Output

Basic analysis:
```
API Method Analysis:
--------------------
GET: 15 (48.4%)
POST: 7 (22.6%)
DELETE: 5 (16.1%)
PUT: 2 (6.5%)
PATCH: 2 (6.5%)
--------------------
Total endpoints: 31
```

With parameter analysis (`--params`):
```
API Method Analysis:
--------------------
GET: 15 (48.4%)
POST: 7 (22.6%)
DELETE: 5 (16.1%)
PUT: 2 (6.5%)
PATCH: 2 (6.5%)
--------------------
Total endpoints: 31

============================================================
Parameter Analysis per Endpoint:
============================================================
POST    /v1/transfers
        Total params: 1, Required: 1
GET     /v1/user//transfers
        Total params: 4, Required: 1
```

## Command-Line Options
```
-t, --target TARGET          Swagger API URL or local JSON file path (required)
--params                     Show parameter counts per endpoint
--methods METHODS            Filter by HTTP methods (comma-separated, e.g., GET,POST,DELETE)
-o, --output FILE            Export results to CSV file
--auth-bearer TOKEN          Bearer token for authentication
--auth-header HEADER         Custom auth header (format: "Header-Name: value")
--auth-basic USER:PASS       Basic authentication (format: "username:password")
-h, --help                   Show help message
```