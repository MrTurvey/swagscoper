# Search Swagger for the number of HTTP methods

## Overview

`swagscoper` is designed to facilitate the security assessment scoping process using Swagger documented APIs.

## Installation

Clone the repository and set up the environment:
```
git clone https://github.com/MrTurvey/swagscoper.git
cd swagscoper
pip install requests
python swagscoper.py
```

## Usage
`swagscoper` will search a Swagger API URL and then output the number of HTTP methods

```
luke@hax:~/tools/swagscoper$ python swagscoper.py 
Enter Swagger UI URL: https://api.pentestlist.com/core/v1/api-docs

API Method Analysis:
--------------------
GET: 54 (38.8%)
PUT: 32 (23.0%)
POST: 24 (17.3%)
DELETE: 9 (6.5%)
OPTIONS: 5 (3.6%)
HEAD: 5 (3.6%)
PATCH: 5 (3.6%)
TRACE: 5 (3.6%)
--------------------
Total endpoints: 139 
```