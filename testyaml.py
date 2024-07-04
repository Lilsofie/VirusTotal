import yaml
import requests

def find_path_template(spec, target_path):
    for path_template in spec['paths']:
        if '{' in path_template:
            template_parts = path_template.split('/')
            target_parts = target_path.split('/')
            if len(template_parts) == len(target_parts):
                match = all(tp.startswith('{') or tp == tp2 for tp, tp2 in zip(template_parts, target_parts))
                if match:
                    return path_template
    return None

# Load OpenAPI spec
with open("test_VirusTotal.yaml", "r") as file:
    spec = yaml.safe_load(file)

# Extract API details
base_url = "https://www.virustotal.com/api/v3"
path_template = "/ip_addresses/{input_ip}"
method = "get"
ip_address = "209.85.208.52"  # Example input value for the path parameter

# Replace path parameter with the actual value
path = path_template.replace("{input_ip}", ip_address)
url = base_url + path

# Find the correct path template in the spec
correct_path_template = find_path_template(spec, path)
if not correct_path_template:
    raise ValueError("Path template not found in OpenAPI spec")

# Extract headers (e.g., Authorization)
headers = {}
if 'security' in spec['paths'][correct_path_template][method]:
    security_schemes = spec['paths'][correct_path_template][method]['security']
    for scheme in security_schemes:
        for scheme_name in scheme:
            security_scheme = spec['components']['securitySchemes'][scheme_name]
            if security_scheme['type'] == 'apiKey' and security_scheme['in'] == 'header':
                headers[security_scheme['name']] = "643e2c5e7896be9df73b863b09e5e798ddc92275eb0a31a390122f71052e7068"  # Replace with your actual API key

# Make the API call
response = requests.request(method.upper(), url, headers=headers)

# Check response
if response.status_code == 200:
    print("API call successful!")
    print("Response:", response.json())
else:
    print("Headers Sent:", headers)
    print(f"API call failed with status code: {response.status_code}")
    print("Response:", response.text)
