import os
import networkx as nx
import nx_arangodb as nxadb
import torch
import cudf
import cugraph
import pandas as pd
import matplotlib.pyplot as plt
import requests
from openai import OpenAI

# Load database credentials securely
os.environ["DATABASE_HOST"] = os.getenv("DATABASE_HOST", "https://tutorials.arangodb.cloud:8529")
os.environ["DATABASE_USERNAME"] = os.getenv("DATABASE_USERNAME", "TUTljyv8qse1qn9ddft3uq2y")
os.environ["DATABASE_PASSWORD"] = os.getenv("DATABASE_PASSWORD", "TUTap9fgtadhotgarn6tss3")
os.environ["DATABASE_NAME"] = os.getenv("DATABASE_NAME", "TUTzyvt1l9z12l6pyhwmyolb")
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY", "9I4UEJweVUdih04Uv8AXcAxs5H8jSQRfwaugcSQYHcI882wSpFvqJQQJ99BAACL93NaXJ3w3AAABACOGkv4f")

# Azure OpenAI API setup
api_base = "https://your-openai-instance.openai.azure.com"
AZURE_MODEL = "gpt-4o"
AZURE_API_KEY = os.environ["OPENAI_API_KEY"]

# Debugging: Check if API credentials are loaded
print(f"🔹 Azure API Key: {'Loaded' if AZURE_API_KEY else 'Missing'}")
print(f"🔹 Azure API Base: {api_base}")

# Function to interact with Azure OpenAI API
def azure_chat(prompt):
    """Interact with GPT-4o via Azure OpenAI API."""
    client = OpenAI(
        api_key=AZURE_API_KEY,
        base_url=api_base
    )
    try:
        response = client.chat.completions.create(
            model=AZURE_MODEL,
            messages=[
                {"role": "system", "content": "A cybersecurity expert."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error with OpenAI API: {e}"

# Function to load CSV data into Pandas DataFrames
def load_csv_data():
    cve_df = pd.read_csv("cve.csv")
    products_df = pd.read_csv("products.csv")
    vendor_products_df = pd.read_csv("vendor_product.csv")
    vendors_df = pd.read_csv("vendors.csv")
    return cve_df, products_df, vendor_products_df, vendors_df

# Function to create a NetworkX vulnerability graph
def create_vulnerability_graph(cve_df, products_df, vendor_products_df, vendors_df):
    print("🔹 Creating vulnerability graph...")
    G = nx.Graph()
    
    # Add CVEs as nodes
    for _, row in cve_df.iterrows():
        G.add_node(row['cve_id'], severity=row['cvss'], description=row['summary'])
    
    # Add product relationships
    for _, row in products_df.iterrows():
        if row['cve_id'] in G:
            G.add_node(row['vulnerable_product'])
            G.add_edge(row['cve_id'], row['vulnerable_product'])
    
    # Add vendor-product relationships
    for _, row in vendor_products_df.iterrows():
        G.add_node(row['vendor'])
        G.add_node(row['product'])
        G.add_edge(row['vendor'], row['product'])
    
    # Add vendor relationships
    for _, row in vendors_df.iterrows():
        if row['vendor'] in G:
            G.add_edge(row['vendor'], row['cve_id'])
    
    print(f"✅ Graph created with {len(G.nodes)} nodes and {len(G.edges)} edges.")
    return G

# Load CSV data
cve_df, products_df, vendor_products_df, vendors_df = load_csv_data()

# Create vulnerability graph
G_nx = create_vulnerability_graph(cve_df, products_df, vendor_products_df, vendors_df)

# Analyze graph
pagerank_scores = nx.pagerank(G_nx)

# Generate vulnerability report
def generate_vulnerability_report():
    high_risk = [
        node for node, data in G_nx.nodes(data=True) 
        if isinstance(data.get("severity"), (int, float)) and float(data["severity"]) >= 7.0
    ]
    if high_risk:
        return azure_chat(f"These vulnerabilities {high_risk} are critical. Suggest mitigations.")
    return "✅ No high-risk vulnerabilities detected."

# Generate report
print("📢 Vulnerability Report:")
print(generate_vulnerability_report())

# Visualize the graph
def visualize_graph(G):
    if len(G.nodes) == 0:
        print("⚠️ No nodes to visualize.")
        return
    print("🔹 Visualizing the graph...")
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, node_color="skyblue", edge_color="gray", font_size=10, node_size=2000)
    plt.savefig("graph.png")
    print("✅ Graph saved as 'graph.png'. Opening now...")
    plt.show()

# Show graph
visualize_graph(G_nx)



