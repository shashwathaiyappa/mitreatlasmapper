from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

_analyzer = AnalyzerEngine()
_anonymizer = AnonymizerEngine()

def redact(text: str):
    if not text:
        return text, []
    results = _analyzer.analyze(text=text, language="en")
    redacted = _anonymizer.anonymize(text=text, analyzer_results=results).text
    entities = sorted({r.entity_type for r in results})
    return redacted, entities
