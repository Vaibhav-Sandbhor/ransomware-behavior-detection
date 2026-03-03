# MAD-CTI: Multi-Agent Cyber Threat Intelligence System

A modular, AI-powered CTI analysis pipeline that classifies dark web text using local LLMs (Ollama).

## Quick Start

```bash
# 1. Install Ollama (https://ollama.com/download) then:
ollama pull llama3.2

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run the pipeline
python main.py

# 4. Run evaluation
python evaluation.py
```

**No API key needed.** Everything runs locally on your machine.

## Architecture

```
Raw Text --> [TranslatorAgent] --> [AnalyzerAgent] --> [RelevancyAgent] --> [CategoryAgent] --> CSV/JSON
```

| Agent | Purpose |
|-------|---------|
| **TranslatorAgent** | Detects language, translates to English |
| **AnalyzerAgent** | Extracts tools, malware, vulns, attack methods |
| **RelevancyAgent** | Classifies as Relevant / Not Relevant |
| **CategoryAgent** | Classifies into Hack / Malware / Vulnerability / N/A |
| **RiskScorerAgent** | Risk score 0.0-1.0 (optional: `--risk-scoring`) |

## Requirements

- **Python 3.10+**
- **Ollama** with `llama3.2` model
- **8GB+ RAM** recommended

## Usage

```bash
python main.py                     # basic run (4 agents)
python main.py --risk-scoring      # with risk scoring (5 agents)
python main.py --dataset data.json # custom dataset
python evaluation.py               # compare against ground truth
```

## Output

- `output/results.json` — full structured output
- `output/results.csv` — tabular summary
- `logs/pipeline_run_<timestamp>.log` — agent reasoning logs

## Project Structure

```
BE_Project/
├── agents/
│   ├── __init__.py        # Package exports
│   ├── base.py            # Abstract base agent (Ollama client)
│   ├── translator.py      # Language detection + translation
│   ├── analyzer.py        # Structured threat analysis
│   ├── relevancy.py       # Relevancy classification
│   ├── category.py        # Category classification
│   └── risk_scorer.py     # Risk scoring (Phase 6)
├── config.py              # Central configuration
├── logger.py              # Structured logging
├── pipeline.py            # Pipeline orchestrator
├── main.py                # CLI entry point
├── evaluation.py          # Evaluation metrics
├── sample_dataset.json    # 5 sample documents
├── requirements.txt       # Python dependencies
├── .env.example           # Environment template
└── .gitignore
```
