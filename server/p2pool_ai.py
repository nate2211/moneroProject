import datetime
import traceback

from google.genai import types
from google.genai.types import Tool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from google import genai
from dotenv import load_dotenv
import os
load_dotenv()


class GeminiChatBot:
    """
    Modern Gemini chatbot using the stateful `chats` module.
    """

    def __init__(self, logger, model_name: str = "gemini-2.5-pro",
                 initial_instruction: str = None):

        self.logger = logger
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.model_name = model_name
        self.initial_instruction = initial_instruction

        # 1. Initialize Client ONCE.
        # Per docs: Client is the entry point.
        self.client = genai.Client(api_key=self.api_key)

        # 2. Define Config (System Instruction goes here)
        # Per docs: genai.types.GenerateContentConfig
        self.config = types.GenerateContentConfig(
            system_instruction=self.initial_instruction,
            temperature=0.1,
            top_p=1.0,
            top_k=40,
            max_output_tokens=65536,
            response_modalities=["TEXT"],
            # Consolidate tools list
            tools=[
                types.Tool(google_search=types.GoogleSearch()),
                # Note: UrlContext is generally implied if not explicitly disabled/configured differently
                # but can be added if specific configuration is needed.
            ]
        )

        # 3. Initialize the Chat Session
        self._start_new_chat()

    def _log(self, msg):
        if self.logger:
            self.logger.log_message(str(msg).rstrip())
        else:
            print(msg)

    def _start_new_chat(self):
        """Helper to start/reset a chat session using client.chats"""
        # Per docs: client.chats.create(model=..., config=...)
        self.chat_session = self.client.chats.create(
            model=self.model_name,
            config=self.config
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(Exception)
    )
    def send_message(self, user_message: str) -> str:
        if not isinstance(user_message, str) or not user_message.strip():
            return "Please enter a non-empty message."

        try:
            # 4. Use send_message on the chat session (Stateful)
            # Per docs: chat.send_message(message) sends history + new msg
            response = self.chat_session.send_message(user_message)
            return response.text

        except Exception as e:
            self._log(f"Error sending message: {e}\n{traceback.format_exc()}")
            # Re-raise for tenacity to handle the retry
            raise e

    def clear_chat_history(self):
        """Resets the chat session without killing the client."""
        self._start_new_chat()
        self._log("Chat history cleared.")