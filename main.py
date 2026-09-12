from reporter import export_to_csv
from log_reader import read_log_file
from parser import parse_log_line
from detector import run_all_detectors
from analyzer import detect_brute_force
log_file="logs/sample.log"
raw_logs=list()
raw_logs=read_log_file(log_file)
all_findings=list()
parsed_logs_list=list()
for sat in raw_logs:
    parsed_log=parse_log_line(sat)
    if parsed_log:
        parsed_logs_list.append(parsed_log)
        finding=run_all_detectors(parsed_log)
        if finding:
            all_findings.append(finding)
aaa=detect_brute_force(parsed_logs_list)
if aaa:
    all_findings.extend(aaa)
print(all_findings)
export_to_csv(all_findings, "output/findings.csv")
