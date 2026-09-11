def detect_brute_force(parsed_log_list):
    if not parsed_log_list:
        return None
    ip_counts=dict()
    #uz=len(parsed_log_list)
    for log in parsed_log_list:
        if "failed" in log["message"].lower():
            if log["source_ip"] in ip_counts:
                ip_counts[log["source_ip"]]+=1
            else:
                ip_counts[log["source_ip"]]=1
    events=list()
    result=dict()
    for ip,counts in ip_counts.items():
        if counts>=3: #threshold
            result={
                "event_type":"BRUTE_FORCE_ATTACK",
                "severity":"HIGH",
                "source_ip":ip,
                "failed_attempts":counts,
                "message":f"{counts} failed login attempts detected from address {ip}."
            }
            events.append(result)
    return events
