class FindingAnalyzer:
    def analyze(self, scanner_results):
        findings = []

        return findings


if __name__ == "__main__":
    analyzer = FindingAnalyzer()

    test_results = [
        {
            "tool": "SecurityHeadersScanner",
            "missing": ["Content-Security-Policy"],
        }
    ]

    findings = analyzer.analyze(test_results)

    print(findings)