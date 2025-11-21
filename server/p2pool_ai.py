import os
import traceback
from dotenv import load_dotenv
from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

load_dotenv()


# 1. Define the custom exception FIRST, so it exists when the decorator needs it.
class RateLimitException(Exception):
    """Custom exception raised when the API sends a 429 or resource exhausted error."""
    pass


class GeminiChatBot:
    """
    Free-Tier optimized Gemini chatbot.
    - Removes Google Search (Grounding) to avoid billing requirements.
    - Uses 'gemini-2.0-flash' (or 1.5-flash) which are free-tier eligible.
    - Aggressive retry logic for Free Tier Rate Limits (429 Errors).
    """

    def __init__(self, logger, model_name: str = "gemini-2.5-flash",
                 initial_instruction: str = None):

        self.logger = logger
        self.api_key = os.getenv("GOOGLE_API_KEY")

        # Defaulting to 2.0 Flash, which is currently free and fast.
        self.model_name = model_name
        self.initial_instruction = initial_instruction

        # Initialize Client
        self.client = genai.Client(api_key=self.api_key)

        # Define Config
        self.config = types.GenerateContentConfig(
            system_instruction=self.initial_instruction,
            temperature=0.7,
            top_p=0.95,
            top_k=40,
            max_output_tokens=65536,
            response_modalities=["TEXT"],
            # Tools list is empty to ensure strict Free Tier compatibility
            tools=[]
        )

        # Initialize the Chat Session
        self._start_new_chat()

    def _log(self, msg):
        if self.logger:
            self.logger.log_message(str(msg).rstrip())
        else:
            print(msg)

    def _start_new_chat(self):
        """Helper to start/reset a chat session."""
        try:
            self.chat_session = self.client.chats.create(
                model=self.model_name,
                config=self.config
            )
        except Exception as e:
            self._log(f"Failed to create chat session: {e}")

    # FREE TIER ADJUSTMENT:
    # This logic waits: 2s, 4s, 8s, 16s, 32s... up to 60s if RateLimitException is raised.
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        # Now RateLimitException is defined and valid here
        retry=retry_if_exception_type(RateLimitException),
        reraise=True,
    )
    def send_message(self, user_message: str) -> str:
        if not isinstance(user_message, str) or not user_message.strip():
            return "Please enter a non-empty message."

        try:
            response = self.chat_session.send_message(user_message)
            return response.text

        except Exception as e:
            # Check if this is a Rate Limit error (HTTP 429 or Resource Exhausted)
            error_str = str(e).lower()
            if "429" in error_str or "resource_exhausted" in error_str:
                self._log(f"Rate limit hit (Free Tier). Retrying in a moment...")
                # Raise the custom error to trigger specific retry logic
                raise RateLimitException("Rate limit exceeded")

            # Log other errors but allow retry if temporary
            self._log(f"API Error: {e}")
            raise e

    def clear_chat_history(self):
        """Resets the chat session without killing the client."""
        self._start_new_chat()
        self._log("Chat history cleared.")