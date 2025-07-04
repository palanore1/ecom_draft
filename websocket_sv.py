import asyncio
import time
import requests
import websockets
import json
import re
import aiohttp
from datetime import datetime
import os

from openai import OpenAI
from config import Config

from app import edit_order_note_by_email, change_address_by_email
from app import app


class ToolHandler:
    def __init__(self, websocket, conversation_state):
        self.websocket = websocket
        self.conversation_state = conversation_state
        self.tool_handlers = {
            "intent_not_found": self.handle_intent_not_found,
            "open_parcel": self.handle_open_parcel,
            "change_address": self.handle_change_address,
            "change_order_details": self.handle_change_order_details,
            "confirm_order": self.handle_confirm_order,
            "decline_order": self.handle_decline_order,
            "confirm_address": self.handle_confirm_address,
            "goodbye": self.handle_goodbye,
        }

    async def handle_tool_call(self, tool_name: str, arguments: dict = None):
        """Handle a tool call by routing it to the appropriate handler"""
        if tool_name in self.tool_handlers:
            return await self.tool_handlers[tool_name](arguments)
        else:
            print(f"Unknown tool called: {tool_name}")
            return "Îmi pare rău, dar nu am putut procesa cererea dumneavoastră."

    async def handle_intent_not_found(self, arguments: dict = None):
        """Handle cases where no specific intent was found"""
        return "Îmi pare rău, dar nu am putut înțelege exact ce doriți. Puteți să reformulați, vă rog?"

    async def handle_open_parcel(self, arguments: dict = None):
        """Handle request to open parcel at delivery"""
        try:
            with app.app_context():
                edit_order_note_by_email(
                    self.conversation_state["user_email"],
                    self.conversation_state["order_id"],
                    "verificare colet",
                )
            return "Am notat comanda pentru verificare colet la livrare."
        except Exception as e:
            print(f"Error handling open_parcel: {e}")
            return "Îmi pare rău, dar nu am putut procesa cererea de verificare colet."

    async def handle_change_address(self, arguments: dict = None):
        """Handle address change request"""
        if not arguments or "new_address" not in arguments:
            return "Vă rog să-mi spuneți noua adresă de livrare."

        new_address = arguments["new_address"]
        try:
            with app.app_context():
                change_address_by_email(
                    self.conversation_state["user_email"],
                    self.conversation_state["order_id"],
                    new_address,
                )
            # Update the conversation state with the new address
            self.conversation_state["formatted_address"] = new_address
            return f"Am notat noua adresă de livrare: {new_address}. Vă rog să confirmați dacă această adresă este corectă."
        except Exception as e:
            print(f"Error handling change_address: {e}")
            return "Îmi pare rău, dar nu am putut actualiza adresa de livrare."

    async def handle_change_order_details(self, arguments: dict = None):
        """Handle order details change request"""
        if not arguments or "changes" not in arguments:
            return "Vă rog să-mi spuneți ce modificări doriți să faceți la comandă."

        changes = arguments["changes"]
        try:
            changes_summary = ", ".join(
                [
                    f"{change['item']}: {change['change_type']} -> {change['new_value']}"
                    for change in changes
                ]
            )
            edit_order_note_by_email(
                self.conversation_state["user_email"],
                self.conversation_state["order_id"],
                changes_summary,
            )
            return f"Am notat următoarele modificări la comandă: {changes_summary}"
        except Exception as e:
            print(f"Error handling change_order_details: {e}")
            return "Îmi pare rău, dar nu am putut procesa modificările la comandă."

    async def handle_confirm_order(self, arguments: dict = None):
        """Handle order confirmation"""
        try:
            await send_call_result_to_server_a(
                self.conversation_state["call_sid"],
                self.conversation_state["to_phone_number"],
                self.conversation_state["user_email"],
                self.conversation_state["order_id"],
                self.conversation_state["type"],
                "confirmed",
            )
            self.conversation_state["order_confirmed"] = True
            if self.conversation_state["requires_address_confirmation"]:
                return f"Perfect! Acum vă rog să confirmați dacă adresa este corectă: {self.conversation_state['formatted_address']}. Puteți confirma adresa sau cereți să o schimbați."
            else:
                return "Perfect! Comanda este confirmată. La revedere!"
        except Exception as e:
            print(f"Error handling confirm_order: {e}")
            return "Îmi pare rău, dar nu am putut confirma comanda."

    async def handle_decline_order(self, arguments: dict = None):
        """Handle order decline"""
        try:
            await send_call_result_to_server_a(
                self.conversation_state["call_sid"],
                self.conversation_state["to_phone_number"],
                self.conversation_state["user_email"],
                self.conversation_state["order_id"],
                self.conversation_state["type"],
                "declined",
            )
            self.conversation_state["order_declined"] = True
            return "Înțeleg că doriți să anulați comanda. La revedere!"
        except Exception as e:
            print(f"Error handling decline_order: {e}")
            return "Îmi pare rău, dar nu am putut anula comanda."

    async def handle_confirm_address(self, arguments: dict = None):
        """Handle address confirmation"""
        try:
            await send_call_result_to_server_a(
                self.conversation_state["call_sid"],
                self.conversation_state["to_phone_number"],
                self.conversation_state["user_email"],
                self.conversation_state["order_id"],
                self.conversation_state["type"],
                "confirmed",
            )
            self.conversation_state["address_confirmed"] = True
            return "Perfect! Comanda este confirmată. La revedere!"
        except Exception as e:
            print(f"Error handling confirm_address: {e}")
            return "Îmi pare rău, dar nu am putut confirma adresa."

    async def handle_goodbye(self, arguments: dict = None):
        """Handle goodbye message"""
        self.conversation_state["call_ended"] = True
        return "La revedere! O zi bună!"


# Create logs directory if it doesn't exist
LOGS_DIR = "conversation_logs"
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Global dictionary to store phone numbers for each websocket
websocket_phones = {}


def log_conversation(phone_number: str, message: str, is_agent: bool = False):
    """
    Log a conversation message to a file specific to the phone number.

    Args:
        phone_number (str): The customer's phone number
        message (str): The message to log
        is_agent (bool): Whether the message is from the agent (True) or customer (False)
    """
    try:
        # Clean phone number for filename
        clean_phone = re.sub(r"\D", "", phone_number)
        log_file = os.path.join(LOGS_DIR, f"{clean_phone}.log")

        # Format timestamp and message
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sender = "Agent" if is_agent else "Customer"

        # Format the log entry
        log_entry = f"[{timestamp}] {sender}: {message}\n"

        # Append to log file
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error logging conversation: {e}")


# SEND REQ BACK TO MAIN SV
async def send_call_result_to_server_a(
    call_sid, to_phone_number, user_email, order_id, type, status, new_address=None
):
    async with aiohttp.ClientSession() as session:
        payload = {
            "call_sid": call_sid,
            "to_phone_number": to_phone_number,
            "user_email": user_email,
            "order_id": order_id,
            "type": type,
            "status": status,
        }
        if new_address:
            payload["new_address"] = new_address

        await session.post(
            "http://37.27.108.19:9000/call-result",
            json=payload,
        )


# OPENAI INTENT CLASSIFICATION
client = OpenAI(api_key=Config.OPENAI_API_KEY)


def format_results(results):
    formatted_results = ""
    for result in results.data:
        formatted_result = (
            f"<result file_id='{result.file_id}' file_name='{result.filename}'>"
        )
        for part in result.content:
            formatted_result += f"<content>{part.text}</content>"
        formatted_results += formatted_result + "</result>"
    return f"<sources>{formatted_results}</sources>"


def agentic_response(
    user_query: str,
    order_value: str,
    transportation_fee: str,
    order_items: str,
    store_name: str,
    formatted_address: str,
    conversation_history: list = None,
):
    """
    This function is used to handle the conversation between the user and the agent.
    The tools the agent can call are:
    - intent_not_found: if there is no real answer in the provided information
    - open_parcel: if the client wants to open the parcel at delivery
    - change_order_details: if the client wants to change the order details (size, color, quantity, etc.)
    - confirm_order: if the client confirms the order
    - decline_order: if the client declines the order
    - confirm_address: if the client confirms the address
    - change_address: if the client wants to change the address
    - goodbye: if the client says goodbye or wants to end the call

    user_query: the user's query
    order_value: the order value
    transportation_fee: the transportation fee
    order_items: the order items
    conversation_history: list of previous conversation messages

    Returns:
    - type: the type of the response
    - response: the response from the agent
    - arguments: the arguments for the tool that was called
    """

    formatted_date = datetime.now().strftime("Today is %A, %B %d, %Y at %H:%M:%S")

    SYSYEM_PROMPT = """You are a professional AI voice agent that speaks fluent Romanian.
Your role is to confirm online orders and answer customer questions about delivery, changes, or issues.
Speak naturally, calmly, and avoid sounding robotic or overly casual.
Always keep responses short, clear, respectful, and professional.
For complex issues, politely direct the customer to human support.

Your main goal is to help the customer confirm their order and address. You should:
	1.	Answer questions about the order, delivery, or address
	2.	Handle requests to change order details or address
	3.	Confirm or decline the order when the customer is ready
	4.	Confirm or decline the address when the customer is ready

The client might ask to open and verify the parcel at delivery. In this case, call the tool open_parcel.

There are 8 tools you can call:
	1.	intent_not_found - when there's no clear intent
	2.	open_parcel - when the client wants to open the parcel at delivery
	3.	change_address - when the client wants to change the delivery address
	4.	change_order_details - when the client wants to change size, color, quantity, etc.
	5.	confirm_order - when the client confirms the order
	6.	decline_order - when the client declines the order
	7.	confirm_address - when the client confirms the address
	8.	goodbye - when the client says goodbye or wants to hang up.

IMPORTANT:
	•	Use change_order_details with new details as the argument.
	•	Use confirm_order when the client confirms that they placed the order.
	•	Use decline_order when the client declines the order.
	•	Only use change_address when youy also have the new address for delivery.
	•	Use goodbye when the client expresses a desire to end the call.
"""

    CONTEXT = f"""
TODAY'S DATE&TIME: {formatted_date}.

ORDER DETAILS:
- STORE NAME: You are calling on behalf of {store_name}.
- ORDER AMOUNT AND SHIPPING FEE: The client's order total value is {order_value} LEI and the transportation fee (separate from the order value) is {transportation_fee} LEI.
- DELIVERY TIME: 1-3 business days
- ITEMS IN ORDER: {order_items}
- SHIPPING ADDRESS: {formatted_address}
"""

    # Build conversation history for context
    messages = [
        {
            "role": "system",
            "content": SYSYEM_PROMPT + "\n" + CONTEXT,
        }
    ]

    # Add conversation history if provided
    if conversation_history:
        for msg in conversation_history:
            messages.append(msg)

    # Add current user query
    messages.append(
        {
            "role": "user",
            "content": user_query,
        }
    )

    completion = client.responses.create(
        model="gpt-4.1-nano",
        input=messages,
        tools=[
            {
                "type": "function",
                "name": "intent_not_found",
                "description": "No answer was found based on the provided context.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
            {
                "type": "function",
                "name": "open_parcel",
                "description": "Open the parcel at delivery.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
            {
                "type": "function",
                "name": "change_address",
                "description": "Change the delivery address.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "new_address": {
                            "type": "string",
                            "description": "The new address to deliver the parcel to.",
                        },
                    },
                    "required": ["new_address"],
                },
                "strict": False,
            },
            {
                "type": "function",
                "name": "change_order_details",
                "description": "Change order items or their specifications (size, color, quantity, etc.).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "changes": {
                            "type": "array",
                            "description": "List of changes to be made to the order items",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "item": {
                                        "type": "string",
                                        "description": "The item to be changed (e.g., 'tricou negru XL')",
                                    },
                                    "change_type": {
                                        "type": "string",
                                        "description": "Type of change (e.g., 'size', 'color', 'quantity', 'remove', 'add')",
                                    },
                                    "new_value": {
                                        "type": "string",
                                        "description": "New value for the change (e.g., 'L' for size, '2' for quantity)",
                                    },
                                },
                                "required": ["item", "change_type", "new_value"],
                            },
                        }
                    },
                    "required": ["changes"],
                },
                "strict": False,
            },
            {
                "type": "function",
                "name": "confirm_order",
                "description": "Confirm the order when the customer agrees to proceed.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
            {
                "type": "function",
                "name": "decline_order",
                "description": "Decline the order when the customer wants to cancel.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
            {
                "type": "function",
                "name": "confirm_address",
                "description": "Confirm the address when the customer agrees it's correct.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
            {
                "type": "function",
                "name": "goodbye",
                "description": "End the call when the customer says goodbye or wants to hang up.",
                "parameters": {"type": "object", "properties": {}, "required": []},
                "strict": False,
            },
        ],
    )

    if completion.output[0].type == "function_call":
        try:
            json_data = json.loads(completion.output[0].arguments)
            return (
                completion.output[0].type,
                completion.output[0].name,
                json_data,
            )
        except:
            return (
                completion.output[0].type,
                completion.output_text,
                None,
            )
    else:
        return (
            completion.output[0].type,
            completion.output_text,
            None,
        )


async def send_text(ws, message):
    # Log agent's message if we have a phone number for this websocket
    if id(ws) in websocket_phones:
        log_conversation(websocket_phones[id(ws)], message, is_agent=True)
    await ws.send(json.dumps({"type": "text", "token": message, "last": True}))


async def end_session(websocket):
    """End the current session"""
    try:
        # Clean up the phone number when the connection is closed
        if id(websocket) in websocket_phones:
            phone = websocket_phones[id(websocket)]
            log_conversation(phone, "Call ended", is_agent=True)
            del websocket_phones[id(websocket)]
        await websocket.close()
    except Exception as e:
        print(f"Error ending session: {e}")


async def handle_connection(websocket):
    # Store the current state of the conversation
    conversation_state = {
        "formatted_address": "",
        "call_sid": "",
        "to_phone_number": "",
        "user_email": "",
        "order_id": "",
        "type": "",
        "order_confirmed": False,
        "order_declined": False,
        "address_confirmed": False,
        "requires_address_confirmation": False,
        "conversation_history": [],
    }

    async for message in websocket:
        print("\n📩 RAW MESSAGE:")
        print(message)

        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            print("⚠️ Could not parse JSON")
            continue

        event_type = data.get("type")
        print("📡 Received event:", event_type)

        if event_type == "setup":
            print("Call started")

            call_sid = data.get("callSid")
            to_phone_number = data.get("to", "")
            custom_params = data.get("customParameters", {})

            # Store phone number in global dictionary when call starts
            if to_phone_number != "":
                websocket_phones[id(websocket)] = to_phone_number
                # Log the start of the conversation
                log_conversation(to_phone_number, "Call started", is_agent=True)

            print("🔍 Custom Parameters:", custom_params)

            order_id = custom_params.get("order_id", "")
            user_email = custom_params.get("user_email", "")
            confirm_address = custom_params.get("confirm_address", "")
            formatted_address = custom_params.get("formatted_address", "")
            type = custom_params.get("type", "")
            order_value = custom_params.get("order_value", "")
            transportation_fee = custom_params.get("delivery_fee", "")
            items_list = custom_params.get("items_list", "")
            store_url = (
                custom_params.get("store_url", "")
                .replace("https://", "")
                .replace("http://", "")
                .rstrip("/")
            )
            initial_message = custom_params.get("initial_message", "")

            if confirm_address == "1":
                conversation_state["requires_address_confirmation"] = True

            # Store the conversation state
            conversation_state.update(
                {
                    "call_sid": call_sid,
                    "to_phone_number": to_phone_number,
                    "user_email": user_email,
                    "order_id": order_id,
                    "type": type,
                    "formatted_address": formatted_address,
                }
            )

            # Initialize the tool handler
            tool_handler = ToolHandler(websocket, conversation_state)

            # Add initial greeting to conversation history
            conversation_state["conversation_history"].append(
                {"role": "assistant", "content": initial_message}
            )

        elif event_type == "prompt":
            transcript = data.get("voicePrompt")
            print("🗣️ User said:", transcript)
            log_conversation(
                conversation_state["to_phone_number"],
                transcript,
                is_agent=False,
            )
            print()

            # Add user message to conversation history
            conversation_state["conversation_history"].append(
                {"role": "user", "content": transcript}
            )

            # Use the AI agent to handle the response
            agent_response = agentic_response(
                user_query=transcript,
                order_value=order_value,
                transportation_fee=transportation_fee,
                order_items=items_list,
                store_name=store_url,
                formatted_address=formatted_address,
                conversation_history=conversation_state["conversation_history"],
            )

            if agent_response[0] == "function_call":
                reply = await tool_handler.handle_tool_call(
                    agent_response[1], agent_response[2]
                )

                if (
                    agent_response[1] == "confirm_address"
                    or (
                        agent_response[1] == "confirm_order"
                        and conversation_state["requires_address_confirmation"] == False
                    )
                    or agent_response[1] == "decline_order"
                    or agent_response[1] == "goodbye"
                ):
                    await send_text(websocket, reply)
                    time.sleep(4)
                    await end_session(websocket)
                else:
                    await send_text(websocket, reply)
            else:
                reply = agent_response[1]
                await send_text(websocket, reply)

            conversation_state["conversation_history"].append(
                {"role": "assistant", "content": reply}
            )

        elif event_type == "end":
            print("Call ended")
            break


async def main():
    print("WebSocket server running on ws://localhost:9001/ws")
    async with websockets.serve(handle_connection, "0.0.0.0", 9001):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
