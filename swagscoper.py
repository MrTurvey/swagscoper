import requests
import json
from collections import Counter
from urllib.parse import urljoin

def analyze_swagger_methods(swagger_url):
    """
    Analyzes a Swagger/OpenAPI specification URL and counts HTTP methods.
    
    Args:
        swagger_url (str): URL to the Swagger UI JSON specification
        
    Returns:
        dict: Count of each HTTP method used in the API
    """
    try:
        # If the URL ends with 'swagger-ui.html', try to find the actual JSON endpoint
        if swagger_url.endswith('swagger-ui.html'):
            # Common paths for Swagger JSON
            possible_paths = [
                'v2/api-docs',
                'swagger/v1/swagger.json',
                'api-docs',
                'swagger.json'
            ]
            
            base_url = swagger_url.split('swagger-ui.html')[0]
            
            # Try each possible path
            for path in possible_paths:
                try:
                    response = requests.get(urljoin(base_url, path))
                    if response.ok:
                        swagger_url = urljoin(base_url, path)
                        break
                except:
                    continue
        
        # Fetch the Swagger JSON
        response = requests.get(swagger_url)
        response.raise_for_status()
        
        # Parse the JSON
        swagger_data = response.json()
        
        # Initialize counter for HTTP methods
        method_counter = Counter()
        
        # Handle both Swagger/OpenAPI 2.0 and 3.0
        if 'swagger' in swagger_data:  # Swagger 2.0
            paths = swagger_data.get('paths', {})
            for path in paths.values():
                for method in path.keys():
                    method_counter[method.upper()] += 1
                    
        elif 'openapi' in swagger_data:  # OpenAPI 3.0
            paths = swagger_data.get('paths', {})
            for path in paths.values():
                for method in path.keys():
                    method_counter[method.upper()] += 1
        
        return dict(method_counter)
    
    except requests.exceptions.RequestException as e:
        return f"Error fetching Swagger documentation: {str(e)}"
    except json.JSONDecodeError:
        return "Error: Invalid JSON response"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def print_method_analysis(url):
    """
    Prints a formatted analysis of HTTP methods from a Swagger URL.
    
    Args:
        url (str): URL to the Swagger UI documentation
    """
    results = analyze_swagger_methods(url)
    
    if isinstance(results, dict):
        print("\nAPI Method Analysis:")
        print("-" * 20)
        total = sum(results.values())
        
        # Sort methods by count (descending)
        sorted_methods = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        for method, count in sorted_methods:
            percentage = (count / total) * 100
            print(f"{method}: {count} ({percentage:.1f}%)")
            
        print("-" * 20)
        print(f"Total endpoints: {total}")
    else:
        print(results)  # Print error message

# Example usage
if __name__ == "__main__":
    swagger_url = input("Enter Swagger UI URL: ")
    print_method_analysis(swagger_url)