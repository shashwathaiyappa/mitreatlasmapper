import asyncio, aiohttp, json, os

URL = os.getenv("APP_URL", "http://localhost:8000/ask")
BURST = int(os.getenv("BURST", "200"))

async def one(i, session):
    payload = {"question": f"Ping {i}"}
    async with session.post(URL, json=payload) as resp:
        await resp.text()

async def main():
    async with aiohttp.ClientSession() as s:
        await asyncio.gather(*[one(i, s) for i in range(BURST)])

if __name__ == "__main__":
    asyncio.run(main())