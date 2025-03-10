import os
import networkx as nx
import nx_arangodb as nxadb
import torch
import cudf
import cugraph
import pandas as pd

from openai import AzureOpenAI


# print(text_to_aql_to_text("What vulnerabilities are present in the graph?"))

from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver
from langchain_community.graphs import ArangoGraph
from langchain_community.chains.graph_qa.arangodb import ArangoGraphQAChain
from langchain_core.tools import tool

# Load database credentials securely using environment variables
os.environ["DATABASE_HOST"] = os.getenv("DATABASE_HOST", "https://tutorials.arangodb.cloud:8529")
os.environ["DATABASE_USERNAME"] = os.getenv("DATABASE_USERNAME", "TUT8ipacx2t02ebj95v26ioo")
os.environ["DATABASE_PASSWORD"] = os.getenv("DATABASE_PASSWORD", "TUTb69rmmvlqygt7dceaxf8d")
os.environ["DATABASE_NAME"] = os.getenv("DATABASE_NAME", "TUTnhcypojdm6nocid8h4x3v")
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "9I4UEJweVUdih04Uv8AXcAxs5H8jSQRfwaugcSQYHcI882wSpFvqJQQJ99BAACL93NaXJ3w3AAABACOGkv4f")

# Azure OpenAI API details

# ------------------------------------------------------------------------------

api_base = "https://thisisoajo.openai.azure.com/"  # Replace with your Azure OpenAI resource URL
AZURE_MODEL = "gpt-4o"
AZURE_API_KEY = os.environ["OPENAI_API_KEY"]  # Using the same environment variable
api_version = "2023-06-01-preview"


def azure_chat(prompt):
    """Interact with GPT-4o via Azure OpenAI API."""
    client = AzureOpenAI(
        api_key=AZURE_API_KEY,
        api_version=api_version,
        base_url=f"{api_base}/openai/deployments/{AZURE_MODEL}"
    )
    response = client.chat.completions.create(
        model=AZURE_MODEL,
        messages=[
            {"role": "system", "content": "A network engineer"},
            {"role": "user", "content": prompt}
        ],
        max_tokens=500,
        temperature=0.7,
    )
    return response.choices[0].message.content.strip()

# Sample CSV Data (Only Four Entries)
vulnerabilities = [
    {"cve_id": "CVE-2019-16548", "mod_date": "2019-11-21 15:15:00", "pub_date": "2019-11-21 15:15:00", "cvss": 6.8, "cwe_code": "352", "cwe_name": "Cross-Site Request Forgery (CSRF)", "summary": "A cross-site request forgery vulnerability in Jenkins Google Compute Engine Plugin 4.1.1 and earlier."},
    {"cve_id": "CVE-2019-16547", "mod_date": "2019-11-21 15:15:00", "pub_date": "2019-11-21 15:15:00", "cvss": 4.0, "cwe_code": "732", "cwe_name": "Incorrect Permission Assignment for Critical Resource", "summary": "Missing permission checks in various API endpoints in Jenkins Google Compute Engine Plugin."},
    {"cve_id": "CVE-2019-16546", "mod_date": "2019-11-21 15:15:00", "pub_date": "2019-11-21 15:15:00", "cvss": 4.3, "cwe_code": "639", "cwe_name": "Authorization Bypass Through User-Controlled Key", "summary": "Jenkins Google Compute Engine Plugin does not verify SSH host keys, enabling man-in-the-middle attacks."},
    {"cve_id": "CVE-2013-2092", "mod_date": "2019-11-20 21:22:00", "pub_date": "2019-11-20 21:15:00", "cvss": 4.3, "cwe_code": "79", "cwe_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "summary": "Cross-site Scripting (XSS) in Dolibarr ERP/CRM 3.3.1 allows remote attackers to inject arbitrary web script."}
]

# Create a Cybersecurity Vulnerability Graph in NetworkX
def create_vulnerability_graph():
    G = nx.Graph()
    for vuln in vulnerabilities:
        cve_id = vuln["cve_id"]
        pub_date = vuln["pub_date"]
        mod_date = vuln["mod_date"]
        cwe_code = vuln["cwe_code"]
        severity = vuln["cvss"]

        # Add CVE Node
        G.add_node(cve_id, severity=severity, summary=vuln["summary"])

        # Add CWE Node & Edge
        if cwe_code:
            cwe_node = f"CWE-{cwe_code}"
            G.add_node(cwe_node, name=vuln["cwe_name"])
            G.add_edge(cve_id, cwe_node, relation="has_cwe")

        # Add Date Nodes & Edges
        G.add_node(pub_date, type="date")
        G.add_edge(cve_id, pub_date, relation="published_on")

        G.add_node(mod_date, type="date")
        G.add_edge(cve_id, mod_date, relation="modified_on")

        # Add CVSS Score Edge
        severity_node = f"CVSS-{severity}"
        G.add_node(severity_node, type="severity")
        G.add_edge(cve_id, severity_node, relation="has_severity")
    
    return G

G_nx = create_vulnerability_graph()

# ------------------------------------------------------------------------------
# Step 2: Store the Graph in ArangoDB using nx_arangodb connection style.
G_adb = nxadb.Graph(incoming_graph_data=G_nx, name="VulnerabilityGraph")

# (Optional) Modify nodes/edges. For example, update a vulnerability's description.
if "CVE-2024-1234" in G_adb.nodes:
    G_adb.nodes["CVE-2024-1234"]["description"] = "Critical SQL injection vulnerability."

# ------------------------------------------------------------------------------
# Step 3: GPU-Accelerated Graph Analytics with CPU Fallback.
def analyze_graph(graph):
    """Compute PageRank using NVIDIA cuGraph if GPU is available, else use NetworkX."""
    if torch.cuda.is_available():
        print("Using GPU with cuGraph")
        # Create a DataFrame of edges for cuGraph.
        gdf = cudf.DataFrame(list(graph.edges()), columns=["source", "destination"])
        G_cu = cugraph.Graph()
        G_cu.from_cudf_edgelist(gdf, source="source", destination="destination")
        pagerank_df = cugraph.pagerank(G_cu)
        # Convert the cudf DataFrame to a dictionary.
        pagerank_scores = {row["vertex"]: row["pagerank"] for row in pagerank_df.to_pandas().to_dict("records")}
    else:
        print("Using CPU with NetworkX")
        pagerank_scores = nx.pagerank(graph)
    return pagerank_scores

pagerank_scores = analyze_graph(G_nx)
print("Pagerank Scores:", pagerank_scores)

# Update the stored ArangoDB graph with PageRank values.
for node, score in pagerank_scores.items():
    if node in G_adb.nodes:
        G_adb.nodes[node]["pagerank"] = score

# ------------------------------------------------------------------------------
# Step 4: Query and Chat with the Graph using GraphRAG capabilities.
# Instead of using the built-in chat method, we now use Azure OpenAI.
azure_response = azure_chat("Hello, which vulnerability has the highest page rank value?")
print("Azure OpenAI Response:", azure_response)

# ------------------------------------------------------------------------------
# Step 5: Define a tool to convert text to AQL and then back to text using Azure OpenAI.
@tool
def text_to_aql_to_text(query: str):
    """
    This tool translates a natural language query into AQL,
    executes the query, and translates the result back into natural language.
    Uses Azure OpenAI for language processing.
    """
    result = azure_chat(query)
    return str(result)

# Optionally, test the tool:
print(text_to_aql_to_text("What vulnerabilities are present in the graph?"))
