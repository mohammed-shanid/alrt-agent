import os
import chromadb

def load_mitre_knowledge():
    persist_directory = os.path.join("data", "chroma_db")
    client = chromadb.PersistentClient(path=persist_directory)
    
    collection = client.get_or_create_collection(name="mitre_techniques")
    
    if collection.count() > 0:
        return
    
    techniques = {
        "T1110": "T1110 Brute Force — adversaries use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "T1021.004": "T1021.004 SSH — adversaries may use Valid Accounts to log into remote machines using Secure Shell.",
        "T1078": "T1078 Valid Accounts — adversaries may obtain and abuse credentials of existing accounts.",
        "T1003": "T1003 OS Credential Dumping — adversaries may attempt to dump credentials to obtain account login information.",
        "T1046": "T1046 Network Service Discovery — adversaries may attempt to get a listing of services running on remote hosts.",
        "T1083": "T1083 File and Directory Discovery — adversaries may enumerate files and directories or search in specific locations.",
        "T1105": "T1105 Ingress Tool Transfer — adversaries may transfer tools from an external system into a compromised environment.",
        "T1059": "T1059 Command and Scripting Interpreter — adversaries may abuse command and script interpreters to execute commands.",
        "T1071": "T1071 Application Layer Protocol — adversaries may communicate using application layer protocols to avoid detection.",
        "T1041": "T1041 Exfiltration Over C2 Channel — adversaries may steal data by exfiltrating it over an existing command and control channel."
    }
    
    ids = list(techniques.keys())
    documents = list(techniques.values())
    
    collection.add(
        ids=ids,
        documents=documents
    )
