import os
import chromadb

def search_mitre(query: str, n_results: int = 3) -> list:
    persist_directory = os.path.join("data", "chroma_db")
    client = chromadb.PersistentClient(path=persist_directory)
    
    collection = client.get_or_create_collection(name="mitre_techniques")
    
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )
    
    if results and "documents" in results and results["documents"]:
        return results["documents"][0]
    return []
