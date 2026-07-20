import json
from pathlib import Path
from urllib.parse import urlparse


class JSONReporter:
    def __init__(self, output_directory="output"):
        self.output_directory = Path(output_directory)

        self.output_directory.mkdir(parents=True,exist_ok=True)

    def save(self, target, filename, data):
        parsed_target = urlparse(target)
        clean_url = (parsed_target.netloc or parsed_target.path).replace(":", "_")

        target_directory = self.output_directory / clean_url
        target_directory.mkdir(parents=True, exist_ok=True)

        report_path = target_directory / filename

        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)

        return report_path



if __name__ == "__main__":
    report = JSONReporter()

    final_path = report.save("https://officemaxpal.com", "json_file.json", {"name": "laith", "age": 15})
    final_path = report.save("https://google.com", "json_file.json", {"name": "laith", "age": 15})

    print(f"Final Reports at {final_path}")
