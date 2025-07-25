import datetime
import traceback

from google.genai import types
from google.genai.types import Tool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from google import genai


class GeminiChatBot:
    """
    Minimal and modern Gemini chatbot using ChatSession and tool support.
    Compatible with retry logic, chat history, and GUI loggers like GeminiLogger.
    """

    def __init__(self, logger, model_name: str = "gemini-2.5-pro",
                 initial_instruction: str = None):

        self.logger = logger
        self.api_key = "AIzaSyCFjDQgqabJL6iQzzkjEpgP02-uKpl_o3w"


        self.model_name = model_name

        self.client = genai.Client(api_key=self.api_key)
        url_context_tool = Tool(
            url_context=types.UrlContext()
        )
        code_execution = types.Tool(code_execution=types.ToolCodeExecution())
        grounding_tool = types.Tool(
            google_search=types.GoogleSearch()
        )

        self.config = types.GenerateContentConfig(
                    temperature=0.1,  # Controls randomness (0 = deterministic)
                    top_p=1.0,  # Nucleus sampling (1.0 = all tokens considered)
                    top_k=40,  # Limits number of tokens to sample from
                    max_output_tokens=65536,  # Max length of response
                    stop_sequences=[],  # List of strings where generation should stop
                    tools=[url_context_tool, code_execution, grounding_tool],
                    response_modalities=["TEXT"],
                )

        self.model = model_name
        self.initial_instruction = initial_instruction

    def _log(self, msg):
        self.logger.log_message(str(msg).rstrip())


    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(Exception)
    )
    def send_message(self, user_message: str) -> str:
        if not isinstance(user_message, str) or not user_message.strip():
            return "Please enter a non-empty message."

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=[user_message],
                config=self.config,
            )

            return response.text
        except Exception as e:
            self._log(f"Error sending message: {e}\n{traceback.format_exc()}")
            return f"Unexpected error: {e}"


    def clear_chat_history(self):
        """Resets the chat session."""
        self.client = genai.Client(api_key=self.api_key)
        self._log("Chat history cleared.")