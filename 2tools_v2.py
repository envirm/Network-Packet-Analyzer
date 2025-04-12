import asyncio
import json
import re
from collections import deque
from qdrant_client import AsyncQdrantClient, models
import numpy as np
from typing import List, Dict, Any
from openai import AsyncOpenAI
from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.prebuilt import tools_condition, ToolNode
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import instructor
from anthropic import AsyncAnthropic
from sklearn.preprocessing import normalize
import aiofiles

#########################
# Multi-Agent Components
#########################
class ModelAgent:
    """
    This agent leverages the React graph (reasoner) to produce an assistant response.
    """
    def __init__(self, rag_system: "RAGSystem"):
        self.rag_system = rag_system

    async def generate_response(self, state: MessagesState) -> str:
        # Ensure the graph is initialized
        if self.rag_system.react_graph is None:
            await self.rag_system.init_graph()

        final_event = None
        # Process the state through the React graph
        async for event in self.rag_system.react_graph.astream(state):
            final_event = event  # final_event holds the latest event; after iteration it contains the final state

        # Extract messages from the final event
        assistant_messages = []
        if final_event:
            for node_result in final_event.values():
                if "messages" in node_result:
                    for msg in node_result["messages"]:
                        assistant_messages.append(msg)
        response_text = "\n".join(msg.content for msg in assistant_messages)
        return response_text

class FirewallAgent:
    """
    This agent simulates a firewall system by detecting IP-like patterns in generated responses.
    When found, it “blocks” them by saving the IP to an internal list.
    """
    def __init__(self):
        self.blocked_ips = []

    def block_ip(self, ip: str):
        if ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            print(f"FirewallAgent: Blocked IP {ip}")

    def check_and_block(self, text: str):
        # A simple regex to detect IP addresses in the text
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        found_ips = re.findall(ip_pattern, text)
        for ip in found_ips:
            self.block_ip(ip)

class ManagerAgent:
    """
    The ManagerAgent orchestrates the conversation: It passes the conversation state to the ModelAgent
    and then gives the response to the FirewallAgent for inspection.
    """
    def __init__(self, model_agent: ModelAgent, firewall_agent: FirewallAgent):
        self.model_agent = model_agent
        self.firewall_agent = firewall_agent

    async def process_conversation(self, state: MessagesState) -> str:
        response = await self.model_agent.generate_response(state)
        self.firewall_agent.check_and_block(response)
        return response

#########################
# RAG System Class
#########################
class RAGSystem:
    def __init__(
        self,
        qdrant_host: str = 'localhost',
        qdrant_port: int = 6333,
        val_uuid: str = "uuid",  # Use this to define collection names
        openai_api_key: str = "sk-OPENAI_API_KEY",
        anthropic_api_key: str = "sk-ANTHROPIC_API_KEY",
        use_memory: bool = True,   # Enable memory if needed
        memory_limit: int = 5       # Maximum number of stored messages
    ):
        # Set collection names based on the provided val_uuid
        self.collection_pdf = f"{val_uuid}_tool_txtpdf"
        self.collection_csv = f"{val_uuid}_tool_csv"
        
        self.qdrant_host = qdrant_host
        self.qdrant_port = qdrant_port
        self.openai_api_key = openai_api_key
        self.anthropic_api_key = anthropic_api_key

        # Asynchronous clients and LLMs initialization
        self.qdrant = AsyncQdrantClient(url=f"http://{qdrant_host}:{qdrant_port}")
        self.openai_client = AsyncOpenAI(api_key=openai_api_key)
        self.llm = ChatOpenAI(openai_api_key=openai_api_key, model_name="gpt-3.5-turbo", temperature=0)
        self.anthropic_client = instructor.from_anthropic(
            client=AsyncAnthropic(api_key=anthropic_api_key)
        )
        
        self.sys_msg = SystemMessage(
            content=(
                "The job is to answer questions and provide accurate information about the store's working hours, "
                "products, prices and general information. Always keep the conversation focused on buyer's offers. "
                "In addition, you are a helpful assistant tasked with using {tools} on inputs where you use "
                "{search_similar} to search for company information and product definitions and use "
                "{filter_and_scroll} to search for more details of products like price. "
                "Continue the conversation until explicitly asked to stop."
            )
        )
        
        self.use_memory = use_memory
        self.memory_limit = memory_limit
        if self.use_memory:
            self.chat_history = deque(maxlen=self.memory_limit)
        else:
            self.chat_history = None
        
        self.react_graph = None
        
        # Instantiate the multi-agent components.
        self.model_agent = ModelAgent(self)
        self.firewall_agent = FirewallAgent()
        self.manager_agent = ManagerAgent(self.model_agent, self.firewall_agent)

    async def save_full_anthropic_response(self, response: Any, filename: str = "anthropic_response.json") -> None:
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(response, default=lambda o: o.__dict__, ensure_ascii=False, indent=4))
        
    async def save_full_embedding_response(self, response: Any, filename: str = "embedding_full_response.json") -> None:
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(response, default=lambda o: o.__dict__, ensure_ascii=False, indent=4))
        
    async def generate_embedding(self, text: str) -> List[float]:
        response = await self.openai_client.embeddings.create(
            model="text-embedding-ada-002",
            input=text
        )
        # Save the full API response to a JSON file
        await self.save_full_embedding_response(response.usage, filename="embedding_full_response.json")
        embedding_data = response.data[0]
        embedding = embedding_data.embedding
        embedding_array = np.array(embedding).reshape(1, -1)
        normalized_embedding = normalize(embedding_array)[0]
        return normalized_embedding.tolist()

    async def search_similar_content(self, query_embedding: List[float], limit: int = 3) -> List[str]:
        search_result = await self.qdrant.search(
            collection_name=self.collection_pdf,
            query_vector=query_embedding,
            limit=limit
        )
        return [hit.payload['text'] for hit in search_result]

    async def search_similar(self, text: str) -> List[str]:
        """Search using embedding."""
        embedding = await self.generate_embedding(text)
        results = await self.search_similar_content(embedding)
        return results

    async def filter_and_scroll(self, user_query: str):
        """Filter data using Anthropic based on the user's query."""
        collection_info = await self.qdrant.get_collection(collection_name=self.collection_csv)
        indexes = collection_info.payload_schema
        formatted_indexes = "\n".join([
            f"- {index_name} - {index.data_type.name}"
            for index_name, index in indexes.items()
        ])

        SYSTEM_PROMPT = (
            "Extract filters from the text query. "
            "The query is enclosed in <query> tags and indexes in <indexes> tags. "
            "Use only the provided indexes, treat multi-word phrases as one, "
            "prices in euro, and ensure exact phrase matches."
        )

        qdrant_filter = await self.anthropic_client.messages.create(
            model="claude-3-haiku-20240307",
            response_model=models.Filter,
            max_tokens=1024,
            messages=[
                {"role": "user", "content": SYSTEM_PROMPT.strip()},
                {"role": "assistant", "content": "Acknowledged."},
                {"role": "user", "content": f"<query>{user_query}</query><indexes>\n{formatted_indexes}\n</indexes>"}
            ],
        )
        
        await self.save_full_anthropic_response(qdrant_filter._raw_response.usage, filename="anthropic_response.json")
        response = await self.qdrant.scroll(
            collection_name=self.collection_csv,
            scroll_filter=qdrant_filter,
            limit=3
        )
        
        return [point for point in response]

    def save_token_usage(self, token_usage: dict, filename: str = 'token_usage.json') -> None:
        filtered_token_usage = {
            key: token_usage[key]
            for key in ["completion_tokens", "prompt_tokens", "total_tokens"]
            if key in token_usage
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(filtered_token_usage, f, ensure_ascii=False, indent=4)
        
    async def reasoner(self, state: MessagesState) -> Dict[str, Any]:
        # Bind the tools with the LLM and use them to respond to the query.
        llm_with_tools = self.llm.bind_tools([self.search_similar, self.filter_and_scroll])
        result = await llm_with_tools.ainvoke([self.sys_msg] + state["messages"])
        return {"messages": [result]}

    async def _create_react_graph_async(self) -> Any:
        builder = StateGraph(MessagesState)
        builder.add_node("reasoner", self.reasoner)
        builder.add_node("tools", ToolNode([self.search_similar, self.filter_and_scroll]))
        builder.add_edge(START, "reasoner")
        builder.add_edge("tools", "reasoner")
        builder.add_conditional_edges(
            "reasoner",
            tools_condition,
            {"tools": "tools", END: END}
        )
        return builder.compile()

    async def init_graph(self):
        self.react_graph = await self._create_react_graph_async()

    def clear_memory(self) -> None:
        """Clear the conversation history."""
        if self.use_memory and self.chat_history is not None:
            self.chat_history.clear()
            print("Memory cleared!")

    async def converse(self, user_input: str) -> str:
        """
        Uses the multi-agent system to process the conversation.
          - The conversation state (including history if enabled) is built.
          - ManagerAgent drives the process by obtaining a response from the ModelAgent.
          - FirewallAgent inspects the final response for any IP addresses to block.
        """
        # Build conversation state with memory if enabled.
        if self.use_memory and self.chat_history:
            state = {'messages': list(self.chat_history) + [HumanMessage(content=user_input)]}
        else:
            state = {'messages': [HumanMessage(content=user_input)]}
        
        # Use ManagerAgent to obtain the response.
        response_text = await self.manager_agent.process_conversation(state)
        
        # Update chat history with the new exchange.
        if self.use_memory:
            self.chat_history.append(HumanMessage(content=user_input))
            self.chat_history.append(SystemMessage(content=response_text))
        
        return response_text

async def main():
    rag_system = RAGSystem(
        use_memory=True,
        memory_limit=5
    )
    await rag_system.init_graph()
    print("Conversation started. Type 'quit' to exit, 'clear' to clear memory.")

    while True:
        try:
            user_input = input("You: ")
            if user_input.lower() in ['quit', 'exit', 'bye']:
                break
            elif user_input.lower() == 'clear':
                rag_system.clear_memory()
                continue

            response = await rag_system.converse(user_input)
            print("Response:", response)
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
