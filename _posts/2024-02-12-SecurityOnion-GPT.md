---
title: SecurityOnion GPT
date: 2024-02-12
categories: [research, hunting]
tags: [homelab, ai]
---

# Introduction
I was recently catching up on some conference videos and saw a talk by Roberto Rodriguez on [Empowering Security Teams with Generative AI: GPT models](https://www.youtube.com/watch?v=TiBIP7kWaks&list=PL7ZDZo2Xu3332bKrXyCb0VEg52nqmMAcv&index=31). This got me thinking about how to integrate GPT to hunting with Security Onion.

**Goals**:
1. Summarize activity found in Security Onion
2. Enrich activity with MITRE ATT&CK attribution
3. Convert English questions to Kibana Query Language to hunt

In this post, I'll tackle goals 1 and 2. I'll do goal 3 in a separate post. These experiments will be conducted in Jupyter lab.

# 1. Summarize activity found in Security Onion
First we need to connect Jupyter to SO to search for malicious activity. I've run some ransomware attacks in the lab, so we'll test out these goals by looking for pre-ransom activity, which includes deleting the Windows Volume Shadow copies as part of [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/).

## Connect to Elasticsearch


```python
!pip3 install pandas openai autogen elasticsearch elasticsearch-dsl python-dotenv
```

```python
import pandas as pd
import os
import json
import openai
import urllib3
import autogen
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q
from dotenv import load_dotenv
```

Here we connect to the Elasticsearch service that's running on SO. `search_so()` is a helper function to reduce boilerplate code when searching for activity.

`terms` is a list of [Elasticsearch DSL](https://elasticsearch-dsl.readthedocs.io/en/latest/) queries. They will take the form of:
```
Q('TYPE', **{field1: value1}),
```
where TYPE is 'match' to do normal or fuzzy searches, 'term' for precise values, or 'range' to look for values between two limits. 'range' will be used for @timestamp field to focus in on when the activity occurred. The `**{}` syntax is needed for the @timestamp field, as the Search DSL documentation says:
> In some cases [Pass all the parameters as keyword arguments] is not possible due to python’s restriction on identifiers - for example if your field is called @timestamp. In that case you have to fall back to unpacking a dictionary: Range(** {'@timestamp': {'lt': 'now'}})



```python
# Security Onion setup
load_dotenv()
soindex='*:so-*'
so_user = os.getenv("SO_USERNAME")
so_pass = os.getenv("SO_PASSWORD")
sohost = os.getenv("SO_HOST")
so_api_key = os.getenv("SO_API_KEY")
es = Elasticsearch([f'https://{sohost}:9200'], ca_certs=False,verify_certs=False, api_key=so_api_key)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def search_so(terms: list, start_date=(datetime.utcnow() - timedelta(days=3)).isoformat(), end_date=datetime.now().isoformat()):
    search = Search(using=es, index=soindex, doc_type='doc')
    search = search.query(
        Q('bool',
          must=terms
        )
    )
    response = search.execute()
    if response.success():
        df = pd.DataFrame((d.to_dict() for d in search.scan()))
        return df
    else:
        print(f"Query failed: {response}")
        return None
```

Verifying that Jupyter and Elasticsearch can communicate:

```python
es.info()
```

   > ObjectApiResponse({'name': 'securityonion', 'cluster_name': 'securityonion', 'cluster_uuid': 'WVA9WFJETpCLgQPeLtGk1A', 'version': {'number': '8.10.4', 'build_flavor': 'default', 'build_type': 'docker', 'build_hash': 'b4a62ac808e886ff032700c391f45f1408b2538c', 'build_date': '2023-10-11T22:04:35.506990650Z', 'build_snapshot': False, 'lucene_version': '9.7.0', 'minimum_wire_compatibility_version': '7.17.0', 'minimum_index_compatibility_version': '7.0.0'}, 'tagline': 'You Know, for Search'})



Now we can search for activity. This will be the equivalent of the querystring
```
[@timestamp: 2023-11-12T00:00:00 TO 2023-11-15T00:00:00] and event.dataset:process_creation and process.command_line:*shadows*
```
Note that periods in the field names get replaced with double underscores.

```python
# Replace 'your_term_field' and 'your_term_value' with your term field and value
field1 = 'event__dataset'
value1 = 'process_creation'
field2 = 'process__command_line'
value2 = '*shadows*'
# Replace 'your_date_field' with your date field
date_field = '@timestamp'

# Replace the date range as needed
start_date = datetime(2023, 11, 12)
end_date = datetime(2023, 11, 15)

# Create a Bool query with Term and Range clauses
terms = [
  Q('match', **{field1: value1}),
  Q('wildcard', **{field2: value2}),
  Q('range', **{date_field: {'gte': start_date, 'lte': end_date}})
]

# Execute the search
response = search_so(terms, start_date, end_date)

# Access the search results
if response is not None:
    df = response
```


```python
df
```


<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>metadata</th>
      <th>agent</th>
      <th>process</th>
      <th>winlog</th>
      <th>log</th>
      <th>message</th>
      <th>tags</th>
      <th>observer</th>
      <th>@timestamp</th>
      <th>file</th>
      <th>ecs</th>
      <th>@version</th>
      <th>host</th>
      <th>event</th>
      <th>user</th>
      <th>hash</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'SCR-ACT-PC2', 'id': '2e5cc8c1-e445-4...</td>
      <td>{'parent': {'entity_id': '{14f46ddd-e36e-6552-...</td>
      <td>{'computer_name': 'SCR-ACT-PC2.blue.local', 'p...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'SCR-ACT-PC2.blue.local'}</td>
      <td>2023-11-14T03:03:10.110Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'SCR-ACT-PC2', 'os': {'build': '1...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': '272245E2988E1E430500B852C4FB5E18'...</td>
    </tr>
    <tr>
      <th>1</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'SCR-ACT-PC2', 'id': '2e5cc8c1-e445-4...</td>
      <td>{'parent': {'entity_id': '{14f46ddd-e36e-6552-...</td>
      <td>{'computer_name': 'SCR-ACT-PC2.blue.local', 'p...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'SCR-ACT-PC2.blue.local'}</td>
      <td>2023-11-14T03:03:10.142Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'SCR-ACT-PC2', 'os': {'build': '1...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': 'C1EDC431CD345F0A0F32019895D13FCE'...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'scr-sales-pc1', 'id': '0ae611f1-d2e3...</td>
      <td>{'parent': {'entity_id': '{5f62a1c2-dc3d-6552-...</td>
      <td>{'computer_name': 'scr-sales-pc1.blue.local', ...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'scr-sales-pc1.blue.local'}</td>
      <td>2023-11-14T02:32:29.137Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'scr-sales-pc1', 'os': {'build': ...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': '272245E2988E1E430500B852C4FB5E18'...</td>
    </tr>
    <tr>
      <th>3</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'scr-sales-pc1', 'id': '0ae611f1-d2e3...</td>
      <td>{'parent': {'entity_id': '{5f62a1c2-dc3d-6552-...</td>
      <td>{'computer_name': 'scr-sales-pc1.blue.local', ...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'scr-sales-pc1.blue.local'}</td>
      <td>2023-11-14T02:32:29.170Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'scr-sales-pc1', 'os': {'build': ...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': 'C1EDC431CD345F0A0F32019895D13FCE'...</td>
    </tr>
    <tr>
      <th>4</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'scr-off-pc1', 'id': 'df9e4617-58fd-4...</td>
      <td>{'parent': {'entity_id': '{7face796-de00-6552-...</td>
      <td>{'computer_name': 'scr-off-pc1.blue.local', 'p...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'scr-off-pc1.blue.local'}</td>
      <td>2023-11-14T02:40:00.081Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'scr-off-pc1', 'os': {'build': '2...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': 'D509661209CA0D9B45580702D62B63C0'...</td>
    </tr>
    <tr>
      <th>5</th>
      <td>{'beat': 'winlogbeat', 'ip_address': '10.10.41...</td>
      <td>{'name': 'scr-off-pc1', 'id': 'df9e4617-58fd-4...</td>
      <td>{'parent': {'entity_id': '{7face796-ddff-6552-...</td>
      <td>{'computer_name': 'scr-off-pc1.blue.local', 'p...</td>
      <td>{'level': 'information'}</td>
      <td>Process Create:\nRuleName: -\nUtcTime: 2023-11...</td>
      <td>[beat-ext, beats_input_codec_plain_applied]</td>
      <td>{'name': 'scr-off-pc1.blue.local'}</td>
      <td>2023-11-14T02:40:00.058Z</td>
      <td>{'hash': {}}</td>
      <td>{'version': '8.0.0'}</td>
      <td>1</td>
      <td>{'hostname': 'scr-off-pc1', 'os': {'build': '2...</td>
      <td>{'code': '1', 'provider': 'Microsoft-Windows-S...</td>
      <td>{'name': 'NT AUTHORITY\SYSTEM'}</td>
      <td>{'imphash': 'D73E39DAB3C8B57AA408073D01254964'...</td>
    </tr>
  </tbody>
</table>
</div>



The process information is a JSON object, so we can use `json_normalize` to pull that information into its own dataframe.


```python
processes = pd.json_normalize(df.process)
```

## Connect to OpenAI
Now we'll set up a connection to OpenAI's API. We'l ask ChatGPT to summarize what happened in the command_line values.


```python
# OpenAI setup
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def chat_gpt(prompt):
    response = openai.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
```


```python
prompt = f"""
Provide a summary of the following commandline activity.
Give me a few sentences summarizing what actually happened based
on the parent and process command_line values.

Review: `{processes[['parent.executable','working_directory','executable', 'command_line']].to_json}`
"""

vss_response = chat_gpt(prompt)
print(vss_response)
```

>    The commandline activity involves executing the command "vssadmin delete shadows /all /quiet" using the cmd.exe executable. This command is being run multiple times, with different parent executables and working directories. The command is initiated by a process with the executable C:\Windows\Temp\6341D6.exe, which then calls the cmd.exe executable with the given command line.


That seems pretty "okay". It's not a great description of why a threat actor would do this. Let's adjust the prompt and see if we can get something better.


```python
prompt = f"""
You are a cyber security analyst and found this activity. Why would a threat actor perform these actions?
Review: `{processes[['parent.executable','working_directory','executable', 'command_line']].to_json}`
"""

vss_response2 = chat_gpt(prompt)
print(vss_response2)
```

  >  Based on the provided activity, it appears that a threat actor has performed the following actions:
    1. Executed a file named "6341D6.exe" located in the "C:\Windows\Temp\" directory with the working directory set to "C:\WINDOWS\system32\".
    2. Executed the command "C:\Windows\System32\cmd.exe" with the working directory set to "C:\WINDOWS\system32\".
    3. Executed the command "vssadmin delete shadows /all /quiet".
    4. Executed the command "C:\Windows\System32\vssadmin.exe".
    5. Executed the command "vssadmin delete shadows /all /quiet".
    6. Executed the command "C:\Windows\System32\vssadmin.exe".
    7. Executed the command "vssadmin delete shadows /all /quiet".
    8. Executed the command "C:\Windows\System32\cmd.exe" with the working directory set to "C:\Windows\system32\".
    From these actions, it can be inferred that the threat actor is attempting to delete Volume Shadow Copies (VSS) on the system. VSS is a feature in Windows that creates backups of files and allows users to restore them to a previous state. By deleting the VSS, the threat actor may be trying to cover their tracks or prevent file recovery tools from accessing previous versions of files, thus hindering potential forensic investigation or restoring system to a previous state.  
    Deleting VSS can be a common tactic used by threat actors involved in activities such as ransomware attacks, where they aim to prevent victims from restoring their files from backup copies. It can also be used to hide the presence of malicious files or activities on the system by removing potential traces.
    As a cyber security analyst, it is important to investigate further, analyze the impact of the VSS deletion, and take appropriate actions to mitigate further risks. This may include conducting a thorough system analysis, monitoring for any additional suspicious activities, and implementing security measures to prevent future unauthorized access.

This is much more relevant, but is also a lot to read through. When we enrich this later, we'll see that we're going to exceed token limitations in the GPT model, so we'd want this summarized more.

# 2. Enrich activity with MITRE ATT&CK attribution
Now let's look at taking what we found above and try to attribute it to threat actors. First we need to create a knowledge base of threat actors that GPT can look at. We do this with [text embeddings](https://realpython.com/chromadb-vector-database/).

## Create text embeddings
[Cyb3rWard0g](https://otrf.github.io/GenAI-Security-Adventures/experiments/RAG/Threat-Intelligence/ATTCK-Groups/source-knowledge/notebook.html) has already parsed ATT&CK groups and stored them as .md files. His repo references a ChromaDB, but the database was not committed. We need to index the markdown files and create the database ourselves. We can copy Roberto's code and run it ourselves.


```python
import glob
from langchain.document_loaders import UnstructuredMarkdownLoader
documents_directory = "/mnt/storage/GenAI-Security-Adventures/experiments/RAG/Threat-Intelligence/ATTCK-Groups/source-knowledge/documents"
# variables
group_files = glob.glob(os.path.join(documents_directory, "*.md"))

# Loading Markdown files
md_docs = []
print("[+] Loading Group markdown files..")
for group in group_files:
    print(f' [*] Loading {os.path.basename(group)}')
    loader = UnstructuredMarkdownLoader(group)
    md_docs.extend(loader.load())

print(f'[+] Number of .md documents processed: {len(md_docs)}')
```

    [+] Loading Group markdown files..
    
    [+] Number of .md documents processed: 134


Next we tokenize the documents.


```python
import tiktoken

tokenizer = tiktoken.encoding_for_model('gpt-3.5-turbo')
token_integers = tokenizer.encode(md_docs[0].page_content, disallowed_special=())
num_tokens = len(token_integers)
token_bytes = [tokenizer.decode_single_token_bytes(token) for token in token_integers]

print(f"token count: {num_tokens} tokens")
print(f"token integers: {token_integers}")
print(f"token bytes: {token_bytes}")
```

   > token count: 3241 tokens

```python
def tiktoken_len(text):
    tokens = tokenizer.encode(
        text,
        disallowed_special=() #To disable this check for all special tokens
    )
    return len(tokens)

# Get token counts
token_counts = [tiktoken_len(doc.page_content) for doc in md_docs]

print(f"""[+] Token Counts:
Min: {min(token_counts)}
Avg: {int(sum(token_counts) / len(token_counts))}
Max: {max(token_counts)}""")
```

    [+] Token Counts:
    Min: 155
    Avg: 1789
    Max: 8131


Here Roberto splits the documents into chunks to deal with token limits.


```python
from langchain.text_splitter import RecursiveCharacterTextSplitter
# Chunking Text
print('[+] Initializing RecursiveCharacterTextSplitter..')
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50,  # number of tokens overlap between chunks
    length_function=tiktoken_len,
    separators=['\n\n', '\n', ' ', '']
)
```

    [+] Initializing RecursiveCharacterTextSplitter..



```python
print('[+] Splitting documents in chunks..')
chunks = text_splitter.split_documents(md_docs)

print(f'[+] Number of documents: {len(md_docs)}')
print(f'[+] Number of chunks: {len(chunks)}')
```

    [+] Splitting documents in chunks..
    [+] Number of documents: 134
    [+] Number of chunks: 694


Next we take the split documents, apply the embedding function to create the vectors, and load them into the database.


```python
from langchain.embeddings.sentence_transformer import SentenceTransformerEmbeddings
from langchain.vectorstores import Chroma
# create the open-source embedding function
embedding_function = SentenceTransformerEmbeddings(model_name="all-mpnet-base-v2")
persist_directory = './chroma_db'
db = Chroma.from_documents(chunks, embedding_function, collection_name="groups_collection", persist_directory=persist_directory)
```


```python
# Roberto's test
query = "What threat actors send text messages to their targets?"
relevant_docs = db.similarity_search(query)

# print results
print(relevant_docs[0].page_content)
```

    Molerats - G0021
    
    Created: 2017-05-31T21:31:55.093Z
    
    Modified: 2021-04-27T20:16:16.057Z
    
    Contributors:
    
    Aliases
    
    Molerats,Operation Molerats,Gaza Cybergang
    
    Description
    
    Molerats is an Arabic-speaking, politically-motivated threat group that has been operating since 2012. The group's victims have primarily been in the Middle East, Europe, and the United States.(Citation: DustySky)(Citation: DustySky2)(Citation: Kaspersky MoleRATs April 2019)(Citation: Cybereason Molerats Dec 2020)
    
    Techniques Used



```python
# Test a search using our technique
query = "What technique is delete the volume shadow copies?"
relevant_docs = db.similarity_search(query)

# print results
print(relevant_docs[0].page_content)
```

    Matrix 
     Domain 
     Platform 
     Technique ID 
     Technique Name 
     Use 
     
     mitre-attack 
     enterprise-attack 
     Linux,macOS,Windows,Network 
     T1090 
     Proxy 
     CopyKittens  has used the AirVPN service for operational activity.(Citation: Microsoft POLONIUM June 2022) 
     
     mitre-attack 
     enterprise-attack 
     PRE 
     T1588.002 
     Tool 
     CopyKittens  has used Metasploit,  Empire , and AirVPN for post-exploitation activities.(Citation: ClearSky and Trend Micro Operation Wilted Tulip July 2017)(Citation: Microsoft POLONIUM June 2022) 
     
     mitre-attack 
     enterprise-attack 
     macOS,Windows,Linux 
     T1564.003 
     Hidden Window 
     CopyKittens  has used  -w hidden  and  -windowstyle hidden  to conceal  PowerShell  windows. (Citation: ClearSky Wilted Tulip July 2017) 
     
     mitre-attack 
     enterprise-attack 
     Linux,macOS,Windows 
     T1560.003 
     Archive via Custom Method 
     CopyKittens  encrypts data with a substitute cipher prior to exfiltration.(Citation: CopyKittens Nov 2015) 
     
     mitre-attack 
     enterprise-attack 
     Windows 
     T1218.011 
     Rundll32 
     CopyKittens  uses rundll32 to load various tools on victims, including a lateral movement tool named Vminst, Cobalt Strike, and shellcode.(Citation: ClearSky Wilted Tulip July 2017) 
     
     mitre-attack 
     enterprise-attack 
     Linux,macOS,Windows 
     T1560.001 
     Archive via Utility 
     CopyKittens  uses ZPP, a .NET console program, to compress files with ZIP.(Citation: ClearSky Wilted Tulip July 2017) 
     
     mitre-attack 
     enterprise-attack 
     Windows 
     T1059.001 
     PowerShell


This was not highly accurate. Roberto's data is based on MITRE's Groups. The technique that I'm looking at is employed by ransomware - a software, not a group. Lockbit does not show up in MITRE's Groups list, nor does it show up in software. We may want to make an additional database that focuses on TTPs. But first, let's try querying OpenAI.

I add on CompressibleAgent to try and overcome the token limitations that are experienced when taking OpenAI's explanation of the observed activity.


```python
# Set up AutoGen config list
config_list = autogen.oai.config_list_from_models(
    model_list=["gpt-3.5-turbo", "gpt-4"]
)

# Set up LLM Config
llm_config = {
    "timeout" : 600,
    "seed" : 42,
    "config_list" : config_list,
    "temperature" : 0
}
```


```python
from autogen.agentchat.contrib.retrieve_assistant_agent import RetrieveAssistantAgent
from autogen.agentchat.contrib.retrieve_user_proxy_agent import RetrieveUserProxyAgent
import chromadb
ragproxyagent = RetrieveUserProxyAgent(
    name="ragproxyagent",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=5,
    retrieve_config={
        "task": "qa",
        "collection_name": "groups_collection",
        "model": config_list[0]["model"],
        "client": chromadb.PersistentClient(path='./chroma_db'),
        "embedding_model": "all-mpnet-base-v2", #Sentence-transformers model
    },
)
```


```python
assistant = RetrieveAssistantAgent(
    name="assistant", 
    system_message="You are a helpful assistant.",
    llm_config=llm_config,
)
```


```python
from autogen.agentchat.contrib.compressible_agent import CompressibleAgent
compressed_assistant = CompressibleAgent(
    name="assistant", 
    system_message="You are a cyber security analyst.",
    llm_config={
        "timeout": 600,
        "cache_seed": 42,
        "config_list": config_list,
    },
    compress_config={
        "mode": "COMPRESS",
        "trigger_count": 600, # set this to a large number for less frequent compression
        "verbose": True, # to allow printing of compression information: contex before and after compression
        "leave_last_n": 2,
    }
)
```

  >  INFO:autogen.token_count_utils:gpt-4 may update over time. Returning num tokens assuming gpt-4-0613.

At this point, Roberto can prompt the RAG agent on different MITRE ATT&CK groups. Lets try asking about the pre-ransomware activity that was found:

```python
assistant.reset()

qa_problem = f"What threat actors use the following techniques: {vss_response2}"
ragproxyagent.initiate_chat(compressed_assistant, problem=qa_problem)
```

>     
    User's question is: What threat actors use the following techniques: Based on the provided activity, it appears that a threat actor has performed the following actions:
    1. Executed a file named "6341D6.exe" located in the "C:\Windows\Temp\" directory with the working directory set to "C:\WINDOWS\system32\".
    2. Executed the command "C:\Windows\System32\cmd.exe" with the working directory set to "C:\WINDOWS\system32\".
    3. Executed the command "vssadmin delete shadows /all /quiet".
    4. Executed the command "C:\Windows\System32\vssadmin.exe".
    5. Executed the command "vssadmin delete shadows /all /quiet".
    6. Executed the command "C:\Windows\System32\vssadmin.exe".
    7. Executed the command "vssadmin delete shadows /all /quiet".
    8. Executed the command "C:\Windows\System32\cmd.exe" with the working directory set to "C:\Windows\system32\".
    From these actions, it can be inferred that the threat actor is attempting to delete Volume Shadow Copies (VSS) on the system. VSS is a feature in Windows that creates backups of files and allows users to restore them to a previous state. By deleting the VSS, the threat actor may be trying to cover their tracks or prevent file recovery tools from accessing previous versions of files, thus hindering potential forensic investigation or restoring system to a previous state.
    Deleting VSS can be a common tactic used by threat actors involved in activities such as ransomware attacks, where they aim to prevent victims from restoring their files from backup copies. It can also be used to hide the presence of malicious files or activities on the system by removing potential traces.
    As a cyber security analyst, it is important to investigate further, analyze the impact of the VSS deletion, and take appropriate actions to mitigate further risks. This may include conducting a thorough system analysis, monitoring for any additional suspicious activities, and implementing security measures to prevent future unauthorized access.
    ...
    assistant (to ragproxyagent):
    Based on the provided activity, the threat actor is attempting to delete Volume Shadow Copies (VSS) on the system.
    --------------------------------------------------------------------------------


This response misses the mark. We can probably make this better by engineering a better prompt. The initial OpenAI response was very wordy - if we can make that first prompt return a more focused response, we can try feeding that OpenAI output into the RAG. Then the RAG should provide a better answer to this question. Let's manually test with a more focused prompt.

```python
assistant.reset()

qa_problem = f"What ransomware focused threat actors delete volume shadow copies?"
ragproxyagent.initiate_chat(compressed_assistant, problem=qa_problem)
```

>  
    User's question is: What ransomware focused threat actors delete volume shadow copies?
    ...
    assistant (to ragproxyagent):
    EXOTIC LILY, Wizard Spider
    --------------------------------------------------------------------------------


The [Wizard Spider page](https://attack.mitre.org/groups/G0102/) says:
> Wizard Spider has used WMIC and vssadmin to manually delete volume shadow copies. Wizard Spider has also used Conti ransomware to delete volume shadow copies automatically with the use of vssadmin.[7]

And [EXOTIC LILY](https://attack.mitre.org/groups/G1011/) says:
> EXOTIC LILY is a financially motivated group that has been closely linked with Wizard Spider and the deployment of ransomware including Conti and Diavol.

This is encouraging - the EXOTIC LILY page does not explicitly say that vssadmin is used, but it seems like the link to Wizard Spider provided enough association to make a connection. So, we'll want to engineer the original prompt to produce output that looks like "this threat actor deleted volume shadow copies". On the other hand, there are several other groups that do the same actions, but those were not returned.

As a control, let's see if the GPT will correctly answer a question about another threat actor. The MITRE group page for Lazarus does not list any volume shadow copy interaction.


```python
assistant.reset()

qa_problem = f"What commands does Lazarus Group use to delete volume shadow copies?"
ragproxyagent.initiate_chat(compressed_assistant, problem=qa_problem)
```

>    User's question is: What commands does Lazarus Group use to delete volume shadow copies?
    ...
    assistant (to ragproxyagent):
    The Lazarus Group does not use specific commands to delete volume shadow copies.
    --------------------------------------------------------------------------------

The GPT correctly identifies that Lazarus does not delete volume shadow copies
# Next steps
At this point, we can manually query Elastic and feed results to a GPT for summarization. Using gpt-3.5 provides okay results and we can mitigate some of its shortcomings (context length, training end date) with RAG. My next goal is to have a GPT save time in creating queries for Elastic. Eventually, I'd like to have an agent that you can provide with a hunting lead, have the agent create and run an Elastic query, then summarize and explain results.
