# CybersecurityAI: Threat Intelligence Navigator

## Overview
CybersecurityAI maps vulnerabilities using AI-driven graph analytics, ranking threats via GPU-accelerated PageRank. It enables real-time monitoring, NLP-driven risk analysis, and intelligent mitigation.

## Architectural Diagram
```
+----------------------+     +---------------------+     +---------------------+
|  User Input (NLP)   | --> | Azure OpenAI (GPT)  | --> | AQL Query Generator |
+----------------------+     +---------------------+     +---------------------+
          |                              |                             |
          v                              v                             v
+----------------------+     +---------------------+     +---------------------+
|  ArangoDB Storage   | <-> | cuGraph Analytics   | <-> |  Graph Visualization |
+----------------------+     +---------------------+     +---------------------+
```
## Installation of test python
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/cybersecurityai.git
   cd cybersecurityai
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   ```sh
   export DATABASE_HOST=<ArangoDB_Host>
   export DATABASE_USERNAME=<Your_Username>
   export DATABASE_PASSWORD=<Your_Password>
   export OPENAI_API_KEY=<Your_Azure_OpenAI_Key>
   ```


## Installation of notebook
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/cybersecurityai.git
   cd cybersecurityai
   ```
2. Install dependencies:
   ```sh
   run the notebooks line by line starting from connecting to colab and then using !pip to install dependancies
   ```
3. Set up environment variables:
   ```sh
   export DATABASE_HOST=<ArangoDB_Host>
   export DATABASE_USERNAME=<Your_Username>
   export DATABASE_PASSWORD=<Your_Password>
   export OPENAI_API_KEY=<Your_Azure_OpenAI_Key>
   ```

## Getting ArangoDB Temporary Storage Credentials
To obtain temporary credentials for ArangoDB storage, visit:
[ArangoDB Cloud Connector](https://github.com/arangodb/adb-cloud-connector?tab=readme-ov-file#arangodb-cloud-connector)

## Usage
1. Run the application:
   ```sh
   python main.py
   ```
2. Query the system for vulnerabilities:
   ```sh
   python query.py "Find the most critical vulnerabilities"
   ```

## Features
- **AI-powered Threat Detection**: Uses GPT-based NLP to analyze vulnerabilities.
- **Graph-based Risk Analysis**: Employs ArangoDB and cuGraph for advanced graph analytics.
- **Real-time Monitoring**: Tracks and updates threats dynamically.
- **Interactive Visualization**: Displays threat intelligence insights in an intuitive manner.

## Future Improvements
- Integration with real-time threat intelligence feeds.
- Support for additional graph-based anomaly detection models.
- Enhanced visualization with interactive dashboards.

## Contributing
Contributions are welcome! Feel free to fork the repo and submit pull requests.

## License
This project is licensed under the MIT License.

