def parse_log_line(log_line):
    pieces=log_line.split()
    if not pieces or len(pieces)<4:
        return None
    log_data=dict()
    log_data["timestamp"]=pieces[0]+" "+pieces[1]
    log_data["source_ip"]=pieces[2]
    log_data["user"]=pieces[3]
    log_data["message"]=" ".join(pieces[4:])
    return log_data