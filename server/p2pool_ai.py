import requests
import json
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import datetime  # For get_current_time tool
import time  # For simulating web search delay
from bs4 import BeautifulSoup  # Import BeautifulSoup for web scraping (retained for scrape_webpage tool)
# Removed: import Google Search # Removed Google Search import
import traceback  # Import traceback to get exception info
import os  # Import os for environment variables (though still hardcoding for now)

# Configure logging for this module (will be overridden if a logger is passed)
logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GeminiChatBot:
    """
    A class to manage interactions with the Gemini model, including chat history,
    improved error handling, and function calling capabilities.
    Designed to be used as a backend for a GUI.
    """

    def __init__(self, logger_instance: logging.Logger, model_name: str = "gemini-2.5-pro",
                 initial_instruction: str = None):
        """
        Initializes the GeminiChatBot.

        Args:
            logger_instance (logging.Logger): A logger instance (e.g., GeminiLogger) to use for logging messages.
            model_name (str): The name of the Gemini model to use (e.g., "gemini-2.5-pro").
            initial_instruction (str, optional): An initial system instruction to
                                                 guide the model's behavior. This
                                                 is added as the first user message
                                                 to set context.
        """

        self.api_key = "AIzaSyCFjDQgqabJL6iQzzkjEpgP02-uKpl_o3w"


        self.logger = logger_instance  # Use the provided logger instance

        # Basic validation for the Gemini API key
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            self.logger.log_message(
                "Gemini API Key is missing or is the default placeholder. Please provide a valid Gemini API key.")


        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        self.chat_history = []
        self.available_tools = self._define_tools()  # Define tools for function calling


        if initial_instruction:
            if not isinstance(initial_instruction, str):
                self.logger.log_message(
                    f"Initial instruction must be a string. Received type: {type(initial_instruction)}. Ignoring.")
            else:
                self.chat_history.append({"role": "user", "parts": [{"text": initial_instruction}]})


    def _define_tools(self) -> list:
        """
        Defines the schema for tools (functions) that the Gemini model can call.
        """
        tools = [
            {
                "function_declarations": [
                    {
                        "name": "get_current_time",
                        "description": "Get the current date and time.",
                        "parameters": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    }
                ]
            }
        ]
        return tools

    def _execute_tool(self, tool_call: dict) -> dict:
        """
        Executes a Python function based on the tool call from the Gemini model.
        """
        function_name = tool_call["name"]
        function_args = tool_call.get("args", {})

        self.logger.log_message(f"DEBUG: Model requested tool call: {function_name} with args {function_args}")

        if function_name == "get_current_time":
            result = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.logger.log_message(f"DEBUG: Executed get_current_time. Result: {result}")
            return {"result": result}
        else:
            self.logger.log_message(f"ERROR: Unknown tool requested: {function_name}")
            return {"error": f"Unknown tool: {function_name}"}

    @retry(
        stop=stop_after_attempt(3),  # Try up to 3 times
        wait=wait_exponential(multiplier=1, min=4, max=10),  # Wait 2^n seconds between retries, min 4s, max 10s
        retry=retry_if_exception_type((requests.exceptions.ConnectionError, requests.exceptions.Timeout))
    )
    def _call_gemini_model(self) -> str:
        """
        Makes an API call to the Gemini model using the current chat history and tools.
        Includes retry logic for transient network issues.

        Returns:
            str: The generated text response from the Gemini model, or a string indicating a tool call.
        """
        if not self.api_key or self.api_key == "YOUR_GEMINI_API_KEY_HERE":
            self.logger.log_message("API Key is missing or invalid. Cannot make API call.")
            return "API Key is missing or invalid. Please configure your API key."

        payload = {
            "contents": self.chat_history,
            "generationConfig": {
                "temperature": 0.7,
                "topK": 40,
                "topP": 1.0,
                "maxOutputTokens": 65535,  # Max output tokens for gemini-2.5-pro
                "stopSequences": []
            },
            "tools": self.available_tools  # Register tools with the model
        }
        # The API key is sent as a query parameter in the URL (e.g., ?key=YOUR_API_KEY),
        # not within the 'contents' of this payload (which is the actual prompt body).

        full_api_url = f"{self.api_url}?key={self.api_key}"

        try:
            response = requests.post(
                full_api_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=180  # Reverted timeout to a more reasonable 180 seconds (3 minutes)
            )
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx).

            result = response.json()

            # --- Handle Function Calls ---
            candidates = result.get("candidates", [])
            if candidates and candidates[0].get("content") and candidates[0]["content"].get("parts"):
                first_part = candidates[0]["content"]["parts"][0]
                if "functionCall" in first_part:
                    tool_call = first_part["functionCall"]
                    self.logger.log_message(f"Model requested tool: {tool_call['name']}")

                    # Execute the tool
                    tool_output = self._execute_tool(tool_call)

                    # --- FIX IS HERE ---
                    # The 'content' field for functionResponse should be the dictionary, not a JSON string.
                    self.chat_history.append({
                        "role": "model",
                        "parts": [{"functionCall": tool_call}]
                    })
                    self.chat_history.append({
                        "role": "tool",
                        "parts": [{"functionResponse": {"name": tool_call["name"], "content": tool_output}}] # Removed json.dumps()
                    })
                    # --- END FIX ---

                    # Make another API call with the tool output to get the model's final response
                    self.logger.log_message("DEBUG: Sending tool output back to model for final response...")
                    return self._call_gemini_model()  # Recursive call to get model's text response

                elif "text" in first_part:
                    generated_text = first_part["text"]
                    # Add the model's text response to the chat history for continuity.
                    self.chat_history.append({"role": "model", "parts": [{"text": generated_text}]})
                    return generated_text

            # If no valid text or function call is found, return a specific message.
            self.logger.log_message("No valid text content or function call received from the model in the response.")
            return "No valid text content or function call received from the model."

        except requests.exceptions.HTTPError as http_err:
            error_message = f"HTTP error occurred: {http_err}"
            try:
                error_details = response.json().get('error', {}).get('message', '')
                error_message += f" - Details: Request failed: {error_details}"
            except json.JSONDecodeError:
                error_message += f" - Raw response: {response.text}"
            self.logger.log_message(error_message)
            raise  # Re-raise for tenacity to catch and retry if it's a retriable HTTP error
        except requests.exceptions.ConnectionError as conn_err:
            self.logger.log_message(f"Connection error occurred: {conn_err} - Please check your internet connection.")
            raise  # Re-raise for tenacity to catch and retry
        except requests.exceptions.Timeout as timeout_err:
            self.logger.log_message(
                f"Timeout error occurred: {timeout_err} - The API request took too long to respond.")
            raise  # Re-raise for tenacity to catch and retry
        except requests.exceptions.RequestException as req_err:
            self.logger.log_message(f"An unexpected request error occurred: {req_err}")
            return f"An unexpected request error occurred: {req_err}"
        except json.JSONDecodeError as json_err:
            self.logger.log_message(f"Failed to decode JSON response: {json_err} - Raw response: {response.text}")
            return f"Failed to decode JSON response: {json_err} - Raw response: {response.text}"
        except Exception as e:
            # Format exception info into the message string
            error_detail = traceback.format_exc()
            self.logger.log_message(f"An unhandled critical error occurred: {e}\n{error_detail}")
            return f"An unexpected critical error occurred: {e}"

    def send_message(self, user_message: str) -> str:
        """
        Adds the user's message to the chat history, calls the Gemini model,
        and returns the model's response. Handles potential recursive calls for tool use.

        Args:
            user_message (str): The message from the user.

        Returns:
            str: The model's response or an error message.
        """
        if not isinstance(user_message, str) or not user_message.strip():
            self.logger.log_message("Attempted to send an empty or non-string message.")
            return "Please enter a non-empty message."

        # Add the user's message to the chat history.
        self.chat_history.append({"role": "user", "parts": [{"text": user_message}]})

        # Call the internal method to get the model's response.
        try:
            return self._call_gemini_model()
        except Exception as e:
            # Catch exceptions re-raised by tenacity after all retries fail
            self.logger.log_message(f"API call failed after multiple retries: {e}")
            return f"Failed to get a response after multiple attempts: {e}"

    def clear_chat_history(self):
        """Clears the current chat history."""
        self.chat_history = []
        self.logger.log_message("Chat history cleared.")