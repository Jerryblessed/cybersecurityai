# CybersecurityAI: Threat Intelligence Navigator

## Overview
CybersecurityAI leverages AI-driven graph analytics to map vulnerabilities, rank threats using GPU-accelerated PageRank, and provide real-time monitoring and NLP-based risk analysis.

## Features
- **Graph-Based Threat Intelligence**: Utilizes ArangoDB, NetworkX, and cuGraph for advanced threat analytics.
- **Natural Language Querying**: Supports AI-driven question-answering for cybersecurity insights.
- **GPU-Accelerated Analysis**: Enhances processing speed using cuGraph.
- **Hybrid Query Execution**: Combines traditional AQL with AI-powered queries.
- **Visualization & Risk Dashboards**: Displays insights using graph visualizations.

## Architecture Diagram
```
                +------------------------------------------------------+
                |               User Interface (UI)                   |
                |   (Web App / CLI / API for queries and visualization) |
                +------------------------------------------------------+
                                      │
                                      ▼
                +------------------------------------------------------+
                |       Natural Language Processing (NLP)              |
                |  - Azure OpenAI (GPT-based query interpretation)      |
                |  - LangChain for query execution                      |
                +------------------------------------------------------+
                                      │
                                      ▼
          +-----------------------------------------------------------+
          |       Graph-Based Threat Intelligence Engine              |
          |  - ArangoDB (Graph database for storing vulnerabilities)  |
          |  - NetworkX & cuGraph (Graph analytics and PageRank)      |
          |  - ArangoGraphQAChain (Hybrid query processing)           |
          +-----------------------------------------------------------+
                                      │
                                      ▼
          +-----------------------------------------------------------+
          |         Cybersecurity Data Processing Layer               |
          |  - CVE Data Import (CSV, real-time feeds)                 |
          |  - Data Enrichment (severity, exploitability analysis)    |
          |  - Graph-based risk ranking (cuGraph PageRank)            |
          +-----------------------------------------------------------+
                                      │
                                      ▼
          +-----------------------------------------------------------+
          |                   Visualization Layer                     |
          |  - Graph-based visualization (ArangoDB UI, matplotlib)    |
          |  - Risk dashboards (Severity heatmaps, ranking graphs)    |
          +-----------------------------------------------------------+
```

## How It Works
1. **User Query:** Users interact via web UI, CLI, or API.
2. **NLP Processing:** Azure OpenAI interprets cybersecurity-related queries.
3. **Graph Intelligence Engine:** ArangoDB and cuGraph process vulnerabilities and rank threats.
4. **Data Processing:** CVE data is enriched, analyzed, and ranked based on exploitability and severity.
5. **Visualization:** Users receive risk assessments via dashboards and graphs.

## Installation & Setup
### Prerequisites
- Python 3.8+
- ArangoDB
- NetworkX & cuGraph
- Azure OpenAI API Key

### Installation Steps
```sh
# Clone repository
git clone https://github.com/Jerryblessed/cybersecurityai.git
cd CybersecurityAI

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export OPENAI_API_KEY="your-azure-api-key"
export DATABASE_HOST="https://arangodb-host"
export DATABASE_USERNAME="your-username"
export DATABASE_PASSWORD="your-password"

# Run the application
python main.py
```

## Usage
- Query cybersecurity risks: `python query.py "What is the most critical vulnerability?"`
- Visualize threat rankings: `python visualize.py`

## Challenges & Learnings
- **Challenges**: Implementing GPU acceleration efficiently, optimizing AQL queries.
- **Learnings**: Effective hybrid querying using AI and AQL, optimizing large-scale graph traversal.

## Future Improvements
- Real-time threat detection using streaming data.
- Integration with security incident response systems.
- Enhanced AI-driven risk mitigation strategies.

## Contributors
- Jeremiah Ope

## License
MIT License
