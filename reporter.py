import csv
import os
def export_to_csv(findings,output_filepath):
    if not findings:
        return None
    folder = os.path.dirname(output_filepath)
    if folder and not os.path.exists(folder):
        os.makedirs(folder)
    fieldnames = ["timestamp", "source_ip", "event_type", "severity", "user", "message", "failed_attempts"]
    with open(output_filepath, mode="w", newline="", encoding="utf-8") as f:
        AAA=csv.DictWriter(f,fieldnames=fieldnames)
        AAA.writeheader()
        AAA.writerows(findings)