import json
import os
import random
import time
from neo4j import GraphDatabase
from langchain_openai import ChatOpenAI
from langchain_community.chains.graph_qa.cypher import GraphCypherQAChain
from langchain_community.graphs import Neo4jGraph
from langchain_core.prompts import PromptTemplate
import tiktoken
from dotenv import load_dotenv
from tqdm import tqdm  # ✅ 진행률/예상 시간 표시용

load_dotenv()
os.environ["OPENAI_API_KEY"] = os.getenv("OPENAI_API_KEY")

PRICE_PER_1K_INPUT = 0.000015
PRICE_PER_1K_OUTPUT = 0.00006

encoding = tiktoken.encoding_for_model("gpt-4o")
total_input_tokens = 0
total_output_tokens = 0
total_cost = 0.0
total_time = 0.0
execution_log = []

llm = ChatOpenAI(model_name="gpt-4o-mini", temperature=0)

db_uri = os.getenv("NEO4J_URI")
db_user = os.getenv("NEO4J_USER")
db_password = os.getenv("NEO4J_PASSWORD")
driver = GraphDatabase.driver(db_uri, auth=(db_user, db_password))

graph = Neo4jGraph(url=db_uri, username=db_user, password=db_password)
cypher_qa = GraphCypherQAChain.from_llm(
    llm=llm,
    graph=graph,
    verbose=True,
    allow_dangerous_requests=True,
)


def count_tokens(text: str) -> int:
    return len(encoding.encode(text))


def load_json(filepath):
    with open(filepath, "r", encoding="utf-8") as file:
        data = json.load(file)
    print(f"🔍 Loaded JSON file: {filepath}")
    print(f"📊 Number of functions: {len(data)}")
    return data


def fetch_graph_data(attack_id):
    """
    Neo4j에서 MitreAttackTechnique 노드를 attack_id로 찾아,
    technique 이름과 description을 가져온 뒤 description을 actions 리스트로 감싸서 리턴.
    불필요한 INVOLVES / Action 라벨 사용 제거함 (경고 방지).
    """
    query = """
    MATCH (t:MitreAttackTechnique {attack_id: $attack_id})
    RETURN t.name AS technique_name,
           t.description AS technique_description
    """
    with driver.session() as session:
        try:
            result = session.run(query, attack_id=attack_id)
            records = list(result)
            if not records:
                print(f"⚠️ No data found for ATT&CK ID {attack_id}.")
                return [{
                    "technique_name": "Unknown Technique",
                    "related_actions": []
                }]

            rec = records[0]
            technique_name = rec.get("technique_name", "Unknown Technique")
            technique_description = rec.get("technique_description")
            related_actions = [technique_description] if technique_description else []

            return [{
                "technique_name": technique_name,
                "related_actions": related_actions
            }]
        except Exception as e:
            print(f"❌ Error executing Cypher query: {e}")
            return [{
                "technique_name": "Unknown Technique",
                "related_actions": []
            }]


def truncate_list(lst, max_length=10):
    if not lst:
        return []
    return random.sample(lst, min(len(lst), max_length))


def generate_procedure(technique_name, indicator, comment, relationships, actions, function_name):
    global total_input_tokens, total_output_tokens, total_cost, total_time, execution_log

    relationships = truncate_list(relationships, 5)
    actions = truncate_list(actions, 5)

    prompt_template = PromptTemplate(
        input_variables=["technique_name", "indicator", "comment", "relationships", "actions"],
        template="""
        You are a Cyber Threat Intelligence Analyst specializing in adversary tactics, techniques, and procedures (TTPs).  
        Your task is to generate a **detailed, yet generalized** step-by-step attack procedure based on function behavior (comment) and related MITRE ATT&CK indicators.  
        
        **Context:**  
        - Technique: {technique_name}  
        - Function Behavior Summary: {comment}  
        - Relevant Indicator: {indicator}  
        - Related Attack Patterns: {relationships}  
        - Common Adversary Actions: {actions}  
        
        **Guidelines:**  
        1. Avoid function-specific details (e.g., direct function names) but include real-world behaviors like API calls (e.g., GetProcAddress, LoadLibraryW).  
        2. Incorporate realistic artifacts (e.g., file paths, registry keys, persistence mechanisms, network traffic).  
        3. Describe adversary behavior comprehensively, ensuring it fits within the context of {technique_name}.  
        4. Each step should describe a concrete action an adversary might take at a higher level while still maintaining realism.  
        5. Ensure variety so that different techniques do not have repetitive descriptions.  
        6. Return the response in JSON format.  
        
        **Output Format:**  
        {{
            "technique": "{technique_name}",
            "procedure": [
                {{"step": 1, "description": "The adversary dynamically loads system libraries using API functions such as LoadLibraryW to evade detection."}},
                {{"step": 2, "description": "A remote connection is established to communicate with a C2 server, often using encrypted HTTP traffic."}},
                {{"step": 3, "description": "Files are dropped into sensitive system directories (e.g., C:\\\\Windows\\\\System32) to establish persistence."}},
                {{"step": 4, "description": "Registry modifications are made under HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run to enable execution on startup."}}
            ]
        }}
        """
    )

    prompt = prompt_template.format(
        technique_name=technique_name,
        indicator=indicator,
        comment=comment,
        relationships=json.dumps(relationships),
        actions=json.dumps(actions),
    )

    input_tokens = count_tokens(prompt)
    start = time.time()

    # ChatOpenAI는 이제 predict()가 없으므로 invoke() 사용
    response_msg = llm.invoke(prompt)
    response_text = response_msg.content

    end = time.time()
    output_tokens = count_tokens(response_text)
    elapsed = end - start

    cost = (input_tokens / 1000) * PRICE_PER_1K_INPUT + (output_tokens / 1000) * PRICE_PER_1K_OUTPUT
    total_input_tokens += input_tokens
    total_output_tokens += output_tokens
    total_cost += cost
    total_time += elapsed

    execution_log.append({
        "function": function_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost": round(cost, 6),
        "time_sec": round(elapsed, 3),
    })

    print(f"🕒 {function_name} | Time: {elapsed:.2f}s | Tokens: {input_tokens} in / {output_tokens} out | 💰 ${cost:.5f}")

    try:
        return json.loads(
            response_text.strip()
            .replace("```json", "")
            .replace("```", "")
        )
    except json.JSONDecodeError:
        print(f"Error parsing GPT output: {response_text}")
        return {}


def process_functions(json_data):
    ttp_results = {}

    # ✅ tqdm으로 함수 개수 기반 진행률 & 예상 시간 표시
    for function, details in tqdm(
        json_data.items(),
        total=len(json_data),
        desc="Processing functions",
    ):
        print(f"\n🔎 Processing function: {function}")
        function_ttps = []

        # ✅ 한 함수 내에서 같은 ATT&CK ID(TTP)는 한 번만 처리
        seen_attack_ids = set()

        for entry in details:
            attack_id = entry.get("ATT&CK ID")
            indicator = entry.get("Indicator", "")
            comment = entry.get("Comment", "")

            if not attack_id:
                print(f"⚠️ Skipping function {function}: No ATT&CK ID found.")
                continue

            if attack_id in seen_attack_ids:
                # 같은 함수에서 같은 TTP(ATT&CK ID) 중복 발생 시 스킵
                print(f"↩️ Skipping duplicate ATT&CK ID {attack_id} for function {function}")
                continue
            seen_attack_ids.add(attack_id)

            graph_data = fetch_graph_data(attack_id)
            if not graph_data:
                continue

            generated_procedure = generate_procedure(
                technique_name=graph_data[0].get("technique_name", "Unknown Technique"),
                indicator=indicator,
                comment=comment,
                relationships=graph_data[0].get("related_relationships", []),  # 키는 유지
                actions=graph_data[0].get("related_actions", []),
                function_name=function,
            )

            if generated_procedure:
                function_ttps.append({
                    "function": function,
                    "attack_id": attack_id,
                    "technique_name": graph_data[0].get("technique_name", "Unknown Technique"),
                    "generated_procedure": generated_procedure,
                })

        if function_ttps:
            ttp_results[function] = function_ttps

    print(f"📊 Total functions processed: {len(ttp_results)}")
    return ttp_results


def main():
    RESULT_OUTPUT_DIR = os.getenv("RESULT_OUTPUT_DIR")
    PROCEDURE_OUTPUT_DIR = os.getenv("PROCEDURE_OUTPUT_DIR")
    LOG_DIR = os.path.join(PROCEDURE_OUTPUT_DIR, "log")
    
    os.makedirs(PROCEDURE_OUTPUT_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    SAMPLE_HASH = os.getenv("SAMPLE_HASH")

    input_filepath = os.path.join(RESULT_OUTPUT_DIR, f"{SAMPLE_HASH}_result.json")
    output_filepath = os.path.join(PROCEDURE_OUTPUT_DIR, f"{SAMPLE_HASH}_result.json")
    log_path = os.path.join(PROCEDURE_OUTPUT_DIR, "log", f"{SAMPLE_HASH}_result.json")

    json_data = load_json(input_filepath)
    ttp_results = process_functions(json_data)

    with open(output_filepath, "w", encoding="utf-8") as out_file:
        json.dump(ttp_results, out_file, indent=4)

    with open(log_path, "w", encoding="utf-8") as log_file:
        json.dump({
            "summary": {
                "total_input_tokens": total_input_tokens,
                "total_output_tokens": total_output_tokens,
                "total_cost": round(total_cost, 6),
                "total_time_sec": round(total_time, 2),
            },
            "details": execution_log,
        }, log_file, indent=4)

    print(f"\n✅ TTP extraction completed.\nResults saved to: {output_filepath}")
    print(f"📄 Log saved to: {log_path}")


if __name__ == "__main__":
    main()
