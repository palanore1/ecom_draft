import asyncio
import websockets
import json
import re
import aiohttp


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


# Expanded response patterns
CONFIRMATION_PATTERNS = [
    r"\b(da|sigur|desigur|bineînțeles|confirm|ok|accept|acept|percect|merge)\b",
    r"\b(este corect|e corect|e bun|este bun)\b",
    r"\b(da, (?:este|e) (?:corect|bun|ok))\b",
    r"\b(confirm|confirmat)\b",
    r"\b(merge|perfect|exact)\b",
]

REJECTION_PATTERNS = [
    r"\b(nu|nu cred|n-aș vrea|nu acum|refuz|resping|niciodata|nu mulțumesc)\b",
    r"\b(nu (?:este|e) (?:corect|bun|ok))\b",
    r"\b(vreau să (?:schimb|modific|corectez))\b",
    r"\b(anulez|anulează|refuz)\b",
    r"\b(nu (?:mai )?vreau)\b",
]

ADDRESS_CHANGE_PATTERNS = [
    r"\b(schimb|modific|corectez|altă|nouă|diferită)\b.*\b(adresă|adresa)\b",
    r"\b(adresa (?:nu|este greșită|e greșită))\b",
    r"\b(vreau (?:să )?(?:schimb|modific|corectez))\b.*\b(adresă|adresa)\b",
]

ORDER_CANCEL_PATTERNS = [
    r"\b(anulez|anulează|refuz|resping)\b.*\b(comandă|comanda)\b",
    r"\b(nu (?:mai )?vreau)\b.*\b(comandă|comanda)\b",
    r"\b(renunț|renunt)\b.*\b(comandă|comanda)\b",
    r"\b(cancel|anulez|refuz)\b",
]


def analyze_response(transcript):
    """
    Analyze the user's response and determine the intent.
    Returns a tuple of (intent, confidence)
    Intent can be: 'confirm', 'reject', 'address_change', 'order_cancel', 'unknown'
    """
    transcript = transcript.lower()

    # Check for order cancellation first (highest priority)
    if any(re.search(pattern, transcript) for pattern in ORDER_CANCEL_PATTERNS):
        return "order_cancel", 1.0

    # Check for address change
    if any(re.search(pattern, transcript) for pattern in ADDRESS_CHANGE_PATTERNS):
        return "address_change", 1.0

    # Check for confirmation
    if any(re.search(pattern, transcript) for pattern in CONFIRMATION_PATTERNS):
        return "confirm", 1.0

    # Check for rejection
    if any(re.search(pattern, transcript) for pattern in REJECTION_PATTERNS):
        return "reject", 1.0

    return "unknown", 0.0


async def send_text(ws, message):
    await ws.send(json.dumps({"type": "text", "token": message, "last": True}))


async def end_session(ws, reason="Session concluded"):
    await ws.send(
        json.dumps({"type": "end", "handoffData": json.dumps({"reason": reason})})
    )


async def handle_connection(websocket):
    # Store the current state of the conversation
    conversation_state = {
        "waiting_for_address_confirmation": False,
        "waiting_for_new_address": False,
        "formatted_address": "",
        "call_sid": "",
        "to_phone_number": "",
        "user_email": "",
        "order_id": "",
        "type": "",
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
            to_phone_number = data.get("to")
            custom_params = data.get("customParameters", {})

            print("🔍 Custom Parameters:", custom_params)
            print("🔍 Confirm Address:", custom_params.get("confirm_address", ""))
            # print(
            #     "🔍 Confirm Address Type:",
            #     type(custom_params.get("confirm_address", "")),
            # )

            order_id = custom_params.get("order_id", "")
            user_email = custom_params.get("user_email", "")
            confirm_address = custom_params.get("confirm_address", "")
            formatted_address = custom_params.get("formatted_address", "")
            type = custom_params.get("type", "")

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

            if str(confirm_address) == "1":
                conversation_state["waiting_for_address_confirmation"] = True
                await send_text(
                    websocket,
                    f"Vă rog să confirmați dacă adresa este corectă: {formatted_address}. "
                    "Puteți confirma adresa, cereți să o schimbați, sau să anulați comanda.",
                )

        elif event_type == "prompt":
            transcript = data.get("voicePrompt")
            print("🗣️ User said:", transcript)

            intent, confidence = analyze_response(transcript)

            if conversation_state["waiting_for_address_confirmation"]:
                if intent == "confirm":
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
                    await end_session(websocket)
                elif intent == "order_cancel":
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
                    await end_session(websocket)
                elif intent == "address_change" or intent == "reject":
                    conversation_state["waiting_for_address_confirmation"] = False
                    conversation_state["waiting_for_new_address"] = True
                    await send_text(
                        websocket,
                        "Vă rog să-mi spuneți noua adresă de livrare. "
                        "Spuneți-o clar și complet, inclusiv strada, numărul, orașul și codul poștal. "
                        "Sau puteți anula comanda dacă doriți.",
                    )
                else:
                    await send_text(
                        websocket,
                        "Nu am înțeles exact. Puteți să confirmați adresa, "
                        "să cereți să o schimbați, sau să anulați comanda.",
                    )

            elif conversation_state["waiting_for_new_address"]:
                if intent == "order_cancel":
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
                    await end_session(websocket)
                else:
                    # Assume any other response is the new address
                    new_address = transcript.strip()
                    await send_text(
                        websocket,
                        f"Am notat noua adresă: {new_address}. Comanda va fi livrată la această adresă. La revedere!",
                    )
                    await send_call_result_to_server_a(
                        conversation_state["call_sid"],
                        conversation_state["to_phone_number"],
                        conversation_state["user_email"],
                        conversation_state["order_id"],
                        conversation_state["type"],
                        "address_updated",
                        new_address,
                    )
                    await end_session(websocket)

            else:
                if intent == "confirm":
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
                    await end_session(websocket)
                elif intent == "order_cancel" or intent == "reject":
                    await send_text(
                        websocket, "În regulă. Poate data viitoare. La revedere!"
                    )
                    await send_call_result_to_server_a(
                        conversation_state["call_sid"],
                        conversation_state["to_phone_number"],
                        conversation_state["user_email"],
                        conversation_state["order_id"],
                        conversation_state["type"],
                        "declined",
                    )
                    await end_session(websocket)
                else:
                    await send_text(
                        websocket,
                        "Nu am înțeles exact. Puteți să confirmați comanda sau să o anulați.",
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
