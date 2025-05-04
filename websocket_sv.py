import asyncio
import websockets
import json
import re
import aiohttp


# SEND REQ BACK TO MAIN SV
async def send_call_result_to_server_a(
    call_sid, to_phone_number, user_email, order_id, type, status
):
    async with aiohttp.ClientSession() as session:
        await session.post(
            "http://37.27.108.19:9000/call-result",
            json={
                "call_sid": call_sid,
                "to_phone_number": to_phone_number,
                "user_email": user_email,
                "order_id": order_id,
                "type": type,
                "status": status,
            },
        )


# HELPERS
affirmatives = {"da", "sigur", "desigur", "bineînțeles", "confirm"}
negatives = {"nu", "nu cred", "n-aș vrea", "nu acum", "refuz"}


def is_affirmative(transcript):
    words = set(re.findall(r"\b\w+\b", transcript.lower()))
    return any(word in words for word in affirmatives)


def is_negative(transcript):
    lower = transcript.lower()
    return any(phrase in lower for phrase in negatives)


async def send_text(ws, message):
    await ws.send(json.dumps({"type": "text", "token": message, "last": True}))


async def end_session(ws, reason="Session concluded"):
    await ws.send(
        json.dumps({"type": "end", "handoffData": json.dumps({"reason": reason})})
    )


async def handle_connection(websocket):
    # path = websocket.path

    # if path != "/ws" and path != "/ws/":
    #     print("Rejected connection with unexpected path:", path)
    #     await websocket.close()
    #     return
    # print("WebSocket connected on", path)

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

            order_id = custom_params.get("order_id", "")
            user_email = custom_params.get("user_email", "")
            type = custom_params.get("type", "")

        elif event_type == "prompt":
            transcript = data.get("voicePrompt")
            print("🗣️ User said:", transcript)

            if is_affirmative(transcript):
                await send_text(
                    websocket, "Perfect! Comanda este confirmată. La revedere!"
                )
                await send_call_result_to_server_a(
                    call_sid, to_phone_number, user_email, order_id, type, "confirmed"
                )
                await end_session(websocket)
            elif is_negative(transcript):
                await send_text(
                    websocket, "În regulă. Poate data viitoare. La revedere!"
                )
                await send_call_result_to_server_a(
                    call_sid, to_phone_number, user_email, order_id, type, "declined"
                )
                await end_session(websocket)
            else:
                await send_text(websocket, "Nu am înțeles. Poți repeta, te rog?")

        elif event_type == "end":
            print("Call ended")
            break


async def main():
    print("WebSocket server running on ws://localhost:9001/ws")
    async with websockets.serve(handle_connection, "0.0.0.0", 9001):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
