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


class ToolHandler:
    def __init__(self, websocket, conversation_state):
        self.websocket = websocket
        self.conversation_state = conversation_state
        self.tool_handlers = {
            "intent_not_found": self.handle_intent_not_found,
            "open_parcel": self.handle_open_parcel,
            "change_address": self.handle_change_address,
            "change_order_details": self.handle_change_order_details,
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
            change_address_by_email(
                self.conversation_state["user_email"],
                self.conversation_state["order_id"],
                new_address,
            )
            return f"Am notat noua adresă de livrare: {new_address}"
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


INSTRUCTION_TEMPLATE = """Instrucțiuni: Clasifică mesajul utilizatorului într-una din următoarele categorii:
- confirm_order
- refuse_order
- confirm_address
- change_address
- others

Intrebare: {bot_question}
Mesaj: "{message}"
"""


def get_intent_openai(bot_question: str, user_response: str) -> str:
    intents = [
        "confirm_order",
        "refuse_order",
        "confirm_address",
        "change_address",
        "others",
    ]

    formatted_prompt = INSTRUCTION_TEMPLATE.format(
        bot_question=bot_question, message=user_response
    )
    response = client.responses.create(model="gpt-4.1-nano", input=formatted_prompt)

    result = "unknown"
    for intent in intents:
        if intent in response.output_text:
            result = intent
            break
    print(f"Predicted intent: {result}")
    return result


def agentic_response(
    user_query: str,
    order_value: str,
    transportation_fee: str,
    order_items: str,
    store_name: str,
    formatted_address: str,
):
    """
    This function is used to handle the conversation between the user and the agent.
    The tools the agent can call are:
    - intent_not_found: if there is no real answer in the provided information
    - open_parcel: if the client wants to open the parcel at delivery
    - change_address: if the client wants to change the delivery address
    - change_order_details: if the client wants to change the order details (size, color, quantity, etc.)

    user_query: the user's query
    order_value: the order value
    transportation_fee: the transportation fee
    order_items: the order items

    Returns:
    - type: the type of the response
    - response: the response from the agent
    - arguments: the arguments for the tool that was called
    """

    formatted_date = datetime.now().strftime("Today is %A, %B %d, %Y at %H:%M:%S")

    SYSYEM_PROMPT = """You are a professional AI voice agent that speaks fluent Romanian. Your role is to confirm online orders and answer customer questions related to their orders (delivery, issues, changes).
Always keep your responses short, clear, respectful, and professional.
Speak naturally, calmly, and avoid sounding robotic or overly casual.
If needed, politely guide the customer to contact human support for complex issues.
The client might ask to open and verify the parcel at delivery. They can do so, call the tool "open_parcel".
If the client wants to change the delivery address, call the tool "change_address".
If the client wants to change the order details (size, color, quantity, etc.), call the tool "change_order_details".
If the shipping address does not look correct, ask the client to confirm the address or change it.

There are 4 tools that you can call:
1. intent_not_found if there is no real answer in the provided information
2. open_parcel if the client wants to open the parcel at delivery
3. change_address if the client wants to change the delivery address; this tool needs to be called with the new address as an argument, if the user does not provide the new address, the tool will not be called and the user will be asked to provide the new address
4. change_order_details if the client wants to change the order details (size, color, quantity, etc.);

IMPORTANT: If the client wants to change the order details, the tool "change_order_details" needs to be called with the new order details as an argument, if the user does not provide the new order details, the tool will not be called and the user will be asked to provide the new order details. If the product they want to change is not in the order, the tool will not be called and the user will be asked to provide the new order details.
"""

    # TODO: skip inent_detect -> full agent
    CONTEXT = f"""
TODAY'S DATE&TIME: {formatted_date}.

ORDER DETAILS:
- STORE NAME: You are calling on behalf of {store_name}.
- ORDER AMOUNT AND SHIPPING FEE: The client's order total value is {order_value} LEI and the transportation fee (separate from the order value) is {transportation_fee} LEI.
- DELIVERY TIME: 1-3 business days
- ITEMS IN ORDER: {order_items}
- SHIPPING ADDRESS: {formatted_address}
"""

    completion = client.responses.create(
        model="gpt-4.1-nano",
        input=[
            {
                "role": "system",
                "content": SYSYEM_PROMPT + "\n" + CONTEXT,
            },
            {
                "role": "user",
                "content": user_query,
            },
        ],
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
        "waiting_for_order_confirmation": False,
        "waiting_for_address_confirmation": False,
        "waiting_for_new_address": False,
        "formatted_address": "",
        "call_sid": "",
        "to_phone_number": "",
        "user_email": "",
        "order_id": "",
        "type": "",
        "retry_count": 0,
        "first_user_question": True,
    }

    async def handle_unknown_response():
        """Handle cases where the system doesn't understand the user"""
        conversation_state["retry_count"] += 1
        if conversation_state["retry_count"] < 3:
            if conversation_state["waiting_for_order_confirmation"]:
                await send_text(
                    websocket,
                    "Nu am înțeles exact. Vă rog să-mi spuneți dacă doriți să confirmați comanda sau să o anulați.",
                )
            elif conversation_state["waiting_for_address_confirmation"]:
                await send_text(
                    websocket,
                    "Nu am înțeles exact. Vă rog să-mi spuneți dacă adresa este corectă sau doriți să o schimbați.",
                )
            elif conversation_state["waiting_for_new_address"]:
                await send_text(
                    websocket,
                    "Nu am înțeles exact. Vă rog să-mi spuneți din nou adresa de livrare.",
                )
        else:
            await send_text(
                websocket,
                "Îmi pare rău, dar nu vă pot înțelege. Vă rog să încercați din nou mai târziu. La revedere!",
            )
            await end_session(websocket)

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
            # Store the conversation state
            conversation_state.update(
                {
                    "call_sid": call_sid,
                    "to_phone_number": to_phone_number,
                    "user_email": user_email,
                    "order_id": order_id,
                    "type": type,
                    "formatted_address": formatted_address,
                    "waiting_for_order_confirmation": True,
                }
            )
            # Initialize the tool handler
            tool_handler = ToolHandler(websocket, conversation_state)

        elif event_type == "prompt":
            transcript = data.get("voicePrompt")
            print("🗣️ User said:", transcript)
            log_conversation(
                conversation_state["to_phone_number"],
                transcript,
                is_agent=False,
            )
            print()

            # intent detection
            if conversation_state["waiting_for_order_confirmation"]:
                intent = get_intent_openai("confirmi comanda?", transcript)
            elif conversation_state["waiting_for_address_confirmation"]:
                intent = get_intent_openai("confirmi adresa?", transcript)
            elif conversation_state["waiting_for_new_address"]:
                pass
            else:
                intent = "unknown"

            if intent == "unknown":
                await handle_unknown_response()
                continue

            if conversation_state["waiting_for_order_confirmation"]:
                if "confirm" in intent:
                    conversation_state["waiting_for_order_confirmation"] = False
                    if str(confirm_address) == "1":
                        conversation_state["waiting_for_address_confirmation"] = True
                        await send_text(
                            websocket,
                            f"Perfect! Acum vă rog să confirmați dacă adresa este corectă: {formatted_address}. "
                            "Puteți confirma adresa sau cereți să o schimbați.",
                        )
                    else:
                        await send_text(
                            websocket, "Perfect! Comanda este confirmată. La revedere!"
                        )
                        await send_call_result_to_server_a(
                            conversation_state["call_sid"],
                            conversation_state["to_phone_number"],
                            conversation_state["user_email"],
                            conversation_state["order_id"],
                            conversation_state["type"],
                            "confirmed",
                        )
                        time.sleep(4)
                        await end_session(websocket)

                elif "refuse" in intent:
                    await send_text(
                        websocket, "Înțeleg că doriți să anulați comanda. La revedere!"
                    )
                    await send_call_result_to_server_a(
                        conversation_state["call_sid"],
                        conversation_state["to_phone_number"],
                        conversation_state["user_email"],
                        conversation_state["order_id"],
                        conversation_state["type"],
                        "declined",
                    )
                    time.sleep(4)
                    await end_session(websocket)

                else:
                    if conversation_state["first_user_question"]:
                        print("first user question")
                        conversation_state["first_user_question"] = False
                        await send_text(
                            websocket,
                            "Va rog sa asteptati un minut sa verific comanda.",
                        )

                    agent_response = agentic_response(
                        user_query=transcript,
                        order_value=order_value,
                        transportation_fee=transportation_fee,
                        order_items=items_list,
                        store_name=store_url,
                        formatted_address=formatted_address,
                    )
                    if agent_response[0] == "function_call":
                        reply = await tool_handler.handle_tool_call(
                            agent_response[1], agent_response[2]
                        )
                    else:
                        reply = agent_response[1]
                    if "?" not in reply:
                        reply += "  Acum doriți să confirmați comanda?"
                    else:
                        conversation_state["waiting_for_order_confirmation"] = False
                    await send_text(
                        websocket,
                        reply,
                    )

            elif conversation_state["waiting_for_address_confirmation"]:
                if "confirm" in intent:
                    await send_text(
                        websocket, "Perfect! Comanda este confirmată. La revedere!"
                    )
                    await send_call_result_to_server_a(
                        conversation_state["call_sid"],
                        conversation_state["to_phone_number"],
                        conversation_state["user_email"],
                        conversation_state["order_id"],
                        conversation_state["type"],
                        "confirmed",
                    )
                    time.sleep(4)
                    await end_session(websocket)

                elif intent == "change_address":
                    conversation_state["waiting_for_address_confirmation"] = False
                    conversation_state["waiting_for_new_address"] = True
                    await send_text(
                        websocket,
                        "Vă rog să-mi spuneți noua adresă de livrare. "
                        "Spuneți-o clar și complet, inclusiv strada, numărul, orașul, județul și codul poștal.",
                    )

                else:
                    agent_response = agentic_response(
                        user_query=transcript,
                        order_value=order_value,
                        transportation_fee=transportation_fee,
                        order_items=items_list,
                        store_name=store_url,
                        formatted_address=formatted_address,
                    )
                    if agent_response[0] == "function_call":
                        reply = await tool_handler.handle_tool_call(
                            agent_response[1], agent_response[2]
                        )
                    else:
                        reply = agent_response[1]
                    if "?" not in reply and "adres" not in reply:
                        reply += "  Acum doriți să confirmați adresa?"
                    await send_text(
                        websocket,
                        reply,
                    )

            elif conversation_state["waiting_for_new_address"]:
                agent_response = agentic_response(
                    user_query="vreau sa schimb adresa de livrare in: " + transcript,
                    order_value=order_value,
                    transportation_fee=transportation_fee,
                    order_items=items_list,
                    store_name=store_url,
                    formatted_address=formatted_address,
                )
                if agent_response[0] == "function_call":
                    reply = await tool_handler.handle_tool_call(
                        agent_response[1], agent_response[2]
                    )
                    try:
                        new_address = agent_response[2]["new_address"]
                        conversation_state["waiting_for_new_address"] = False
                        conversation_state["waiting_for_address_confirmation"] = True
                        conversation_state["formatted_address"] = new_address
                        await send_text(
                            websocket,
                            f"Am notat noua adresă: {new_address}. Vă rog să confirmați dacă această adresă este corectă. "
                            "Puteți confirma adresa sau cereți să o schimbați din nou.",
                        )
                    except:
                        await send_text(
                            websocket,
                            "Nu am înțeles adresa. Vă rog să o spuneți din nou.",
                        )
                        continue
                else:
                    reply = agent_response[1]
                    await send_text(
                        websocket, "Nu am înțeles adresa. Vă rog să o spuneți din nou."
                    )
                    continue
            else:  # if the user is not waiting for order confirmation or address confirmation
                agent_response = agentic_response(
                    user_query=transcript,
                    order_value=order_value,
                    transportation_fee=transportation_fee,
                    order_items=items_list,
                    store_name=store_url,
                    formatted_address=formatted_address,
                )
                if agent_response[0] == "function_call":
                    reply = await tool_handler.handle_tool_call(
                        agent_response[1], agent_response[2]
                    )
                else:
                    reply = agent_response[1]
                if "?" not in reply:
                    reply += "  Acum doriți să confirmați comanda?"
                    conversation_state["waiting_for_order_confirmation"] = True
                await send_text(
                    websocket,
                    reply,
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
