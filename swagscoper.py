"""
swagscoper - Swagger/OpenAPI API security assessment scoping tool.

Analyzes Swagger/OpenAPI specifications to provide method counts and parameter
analysis for security assessment planning.
"""

import argparse
import base64
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin

import requests


# HTTP methods recognized by the tool
VALID_HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'}

# Common Swagger JSON endpoint paths
SWAGGER_JSON_PATHS = [
    'v2/api-docs',
    'swagger/v1/swagger.json',
    'api-docs',
    'swagger.json'
]


def load_swagger_data(target, auth_header=None):
    """
    Load Swagger/OpenAPI specification from URL or local file.

    Args:
        target: URL to Swagger API or path to local JSON file
        auth_header: Optional authentication headers dictionary

    Returns:
        Parsed Swagger/OpenAPI JSON data as dictionary

    Raises:
        requests.exceptions.RequestException: If URL fetch fails
        json.JSONDecodeError: If JSON parsing fails
        FileNotFoundError: If local file not found
    """
    # Check if target is a local file
    if Path(target).exists():
        with open(target, 'r', encoding='utf-8') as f:
            return json.load(f)

    # Otherwise treat as URL
    headers = auth_header or {}

    # Auto-detect JSON endpoint from swagger-ui.html
    if target.endswith('swagger-ui.html'):
        base_url = target.split('swagger-ui.html')[0]
        target = _find_swagger_json_endpoint(base_url, headers) or target

    # Fetch the Swagger JSON
    response = requests.get(target, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()


def _find_swagger_json_endpoint(base_url, headers):
    """
    Try to find the actual JSON endpoint from common Swagger paths.

    Args:
        base_url: Base URL without swagger-ui.html
        headers: Request headers dictionary

    Returns:
        Full URL to JSON endpoint if found, None otherwise
    """
    for path in SWAGGER_JSON_PATHS:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, headers=headers, timeout=10)
            if response.ok:
                return url
        except requests.exceptions.RequestException:
            continue
    return None


def _count_endpoint_parameters(path_item, operation):
    """
    Count parameters for a specific endpoint operation.

    Args:
        path_item: Path-level configuration dictionary
        operation: Operation-level configuration dictionary

    Returns:
        Tuple of (total_params, required_params)
    """
    param_count = 0
    required_params = 0

    # Path-level parameters
    if 'parameters' in path_item and isinstance(path_item['parameters'], list):
        param_count += len(path_item['parameters'])
        required_params += sum(1 for p in path_item['parameters'] if p.get('required', False))

    # Operation-level parameters
    if 'parameters' in operation and isinstance(operation['parameters'], list):
        param_count += len(operation['parameters'])
        required_params += sum(1 for p in operation['parameters'] if p.get('required', False))

    # Request body (OpenAPI 3.0)
    if 'requestBody' in operation:
        param_count += 1
        if operation['requestBody'].get('required', False):
            required_params += 1

    return param_count, required_params


def analyze_swagger_methods(target, auth_header=None, count_params=False, method_filter=None):
    """
    Analyze a Swagger/OpenAPI specification and count HTTP methods.

    Args:
        target: URL to Swagger API or path to local JSON file
        auth_header: Optional authentication headers dictionary
        count_params: Whether to count parameters per endpoint
        method_filter: List of HTTP methods to filter (e.g., ['GET', 'POST'])

    Returns:
        Dictionary containing analysis results:
        - 'methods': Dict of method counts
        - 'endpoints': List of endpoint details (if count_params=True)
        Returns error string if analysis fails.
    """
    try:
        # Load the Swagger data
        swagger_data = load_swagger_data(target, auth_header)

        # Initialize counters
        method_counter = Counter()
        endpoint_params = []

        # Get paths (works for both Swagger 2.0 and OpenAPI 3.0)
        paths = swagger_data.get('paths', {})

        for path_name, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                method_upper = method.upper()

                # Skip non-method keys like 'parameters', 'summary', etc.
                if method_upper not in VALID_HTTP_METHODS:
                    continue

                # Apply method filter if specified
                if method_filter and method_upper not in method_filter:
                    continue

                method_counter[method_upper] += 1

                # Count parameters if requested
                if count_params and isinstance(operation, dict):
                    param_count, required_params = _count_endpoint_parameters(path_item, operation)

                    endpoint_params.append({
                        'method': method_upper,
                        'path': path_name,
                        'total_params': param_count,
                        'required_params': required_params
                    })

        result = {'methods': dict(method_counter)}

        if count_params:
            result['endpoints'] = endpoint_params

        return result

    except requests.exceptions.RequestException as e:
        return f"Error fetching Swagger documentation: {e}"
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON response - {e}"
    except FileNotFoundError:
        return f"Error: File not found: {target}"
    except Exception as e:
        return f"Unexpected error: {e}"


def export_to_csv(results, output_file):
    """
    Export analysis results to CSV file.

    Args:
        results: Analysis results dictionary from analyze_swagger_methods
        output_file: Path to output CSV file
    """
    if isinstance(results, str):
        print(f"Error: Cannot export - {results}")
        return

    methods = results.get('methods', {})
    endpoints = results.get('endpoints', [])

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if endpoints:
                # Export detailed endpoint data
                fieldnames = ['method', 'path', 'total_params', 'required_params']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(endpoints)
            else:
                # Export method summary
                writer = csv.writer(csvfile)
                writer.writerow(['Method', 'Count', 'Percentage'])
                total = sum(methods.values())

                for method, count in sorted(methods.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / total) * 100 if total > 0 else 0
                    writer.writerow([method, count, f"{percentage:.1f}%"])

                writer.writerow(['Total', total, '100%'])

        print(f"\n✓ Results exported to {output_file}")

    except IOError as e:
        print(f"Error writing CSV file: {e}")


def _format_percentage(count, total):
    """Calculate and format percentage."""
    return (count / total) * 100 if total > 0 else 0


def print_method_analysis(results):
    """
    Print a formatted analysis of HTTP methods to console.

    Args:
        results: Analysis results dictionary from analyze_swagger_methods
    """
    if isinstance(results, str):
        print(results)  # Print error message
        return

    methods = results.get('methods', {})
    endpoints = results.get('endpoints', [])

    print("\nAPI Method Analysis:")
    print("-" * 20)

    total = sum(methods.values())
    sorted_methods = sorted(methods.items(), key=lambda x: x[1], reverse=True)

    for method, count in sorted_methods:
        percentage = _format_percentage(count, total)
        print(f"{method}: {count} ({percentage:.1f}%)")

    print("-" * 20)
    print(f"Total endpoints: {total}")

    # Print parameter analysis if available
    if endpoints:
        print("\n" + "=" * 60)
        print("Parameter Analysis per Endpoint:")
        print("=" * 60)
        for ep in endpoints:
            print(f"{ep['method']:7} {ep['path']}")
            print(f"        Total params: {ep['total_params']}, Required: {ep['required_params']}")


def _build_auth_header(args):
    """
    Build authentication header from command-line arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Authentication headers dictionary or None
    """
    if args.auth_bearer:
        return {'Authorization': f'Bearer {args.auth_bearer}'}

    if args.auth_header:
        if ':' not in args.auth_header:
            raise ValueError("--auth-header must be in format 'Header-Name: value'")
        key, value = args.auth_header.split(':', 1)
        return {key.strip(): value.strip()}

    if args.auth_basic:
        encoded = base64.b64encode(args.auth_basic.encode()).decode()
        return {'Authorization': f'Basic {encoded}'}

    return None


def _parse_method_filter(methods_arg):
    """
    Parse method filter from command-line argument.

    Args:
        methods_arg: Comma-separated string of HTTP methods

    Returns:
        List of uppercase HTTP methods or None
    """
    if not methods_arg:
        return None
    return [m.strip().upper() for m in methods_arg.split(',')]


def main():
    """Main entry point for the CLI application."""
    parser = argparse.ArgumentParser(
        description='Analyze Swagger/OpenAPI specifications for security assessment scoping',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze a URL
  python swagscoper.py -t https://api.example.com/v2/api-docs

  # Analyze a local file
  python swagscoper.py -t input.json

  # Filter specific methods
  python swagscoper.py -t input.json --methods GET,POST

  # Export to CSV
  python swagscoper.py -t input.json --params -o output.csv

  # With authentication (Bearer token)
  python swagscoper.py -t https://api.example.com/swagger.json --auth-bearer YOUR_TOKEN

  # With API key
  python swagscoper.py -t https://api.example.com/api-docs --auth-header "X-API-Key: YOUR_KEY"

  # Show parameter counts
  python swagscoper.py -t input.json --params
        '''
    )

    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Swagger API URL or local JSON file path'
    )

    parser.add_argument(
        '--params',
        action='store_true',
        help='Show parameter counts per endpoint'
    )

    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Export results to CSV file'
    )

    parser.add_argument(
        '--methods',
        metavar='METHODS',
        help='Filter by HTTP methods (comma-separated, e.g., GET,POST,DELETE)'
    )

    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        '--auth-bearer',
        metavar='TOKEN',
        help='Bearer token for authentication'
    )
    auth_group.add_argument(
        '--auth-header',
        metavar='HEADER',
        help='Custom auth header (format: "Header-Name: value")'
    )
    auth_group.add_argument(
        '--auth-basic',
        metavar='USER:PASS',
        help='Basic authentication (format: "username:password")'
    )

    args = parser.parse_args()

    try:
        # Build authentication header
        auth_header = _build_auth_header(args)

        # Parse method filter
        method_filter = _parse_method_filter(args.methods)

        # Analyze the API
        results = analyze_swagger_methods(
            args.target,
            auth_header,
            args.params,
            method_filter
        )

        # Print results
        print_method_analysis(results)

        # Export to CSV if requested
        if args.output:
            export_to_csv(results, args.output)

    except ValueError as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
