
def detect_failed_login(parsed_login):
    if not parsed_login:
        return None
    if "failed" in parsed_login["message"].lower():
        result={
        "timestamp": parsed_login["timestamp"],
        "source_ip": parsed_login["source_ip"],
        "event_type": "FAILED_LOGIN",
        "severity": "LOW",
        "user": parsed_login["user"],
        "message": parsed_login["message"]}
        return result
    return None 
def detect_sql_inj(parsed_login):
    if not parsed_login:
        return None
    if "'or '1'='1'" in parsed_login["message"].lower() or "union select" in parsed_login["message"].lower() or "--" in parsed_login["message"].lower():
        result={
        "timestamp": parsed_login["timestamp"],
        "source_ip": parsed_login["source_ip"],
        "event_type": "SQL_INJECTION",
        "severity": "HIGH",
        "user": parsed_login["user"],
        "message": parsed_login["message"]}
        return result
    return None
def detect_directory_traversal(parsed_login):
    if not parsed_login:
        return None
    m=parsed_login["message"].lower()
    if "../" in m or "..\\" in m or "/etc/passwd" in m or "win.ini" in m:
        result={
        "timestamp": parsed_login["timestamp"],
        "source_ip": parsed_login["source_ip"],
        "event_type": "DIRECTORY_TRAVERSAL",
        "severity": "HIGH",
        "user": parsed_login["user"],
        "message": parsed_login["message"]}
        return result
    return None       
def run_all_detectors(parsed_login):
    if not parsed_login:
        return None
    findings=detect_failed_login(parsed_login)
    if findings:
        return findings
    findings=detect_sql_inj(parsed_login)
    if findings:
        return findings
    findings=detect_directory_traversal(parsed_login)
    if findings:
        return findings    
    return None