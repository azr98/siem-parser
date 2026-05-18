
import json
import pandas as pd
import re


def normalise_severity(raw):
    mappings = {
        "error": "high",
        "critical": "critical",
        "warn": "medium",
        "info": "info",
        "information": "info",
        "debug": "low"
    }

    return mappings.get(raw, "info")

def parse_railway_logs(path):
    data = json.load(open(path))
    output = []
    body = []
    for log in data:
        if '{' in log['message']:
            message = log['message'].split(' {')[0].strip()
            severity = normalise_severity(log['severity'].strip().lower())
            timestamp = log['timestamp'].strip()
            body = []

        elif '}' not in log['message']:
            body_key = log['message'].split(':')[0].strip()
            body_value_reg = re.findall(r"'(.*?)'",log['message'], re.DOTALL) 
            if body_value_reg:
                body_value = body_value_reg[0].strip()
            body.append(f"{body_key}: '{body_value}'")
        elif '}' in log['message']:
            output.append({
                    'message': message,
                    'severity': severity,
                    'timestamp': timestamp,
                    'body': body
                })

    return output

if __name__ == "__main__":
    parsed_logs = parse_railway_logs('./data/railway-logs.json')
    print(parsed_logs[:15])


    

