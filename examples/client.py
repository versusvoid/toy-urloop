#!/usr/bin/env python3

import asyncio
import aiohttp

import urloop


async def main():
    async with aiohttp.ClientSession() as session:
        async with session.get('https://python.org') as response:
            print("Status:", response.status)
            print("Content-type:", response.headers['content-type'])

            html = await response.text()
            print("Body:", html[:15], '...')


asyncio.set_event_loop_policy(urloop.URingEventLoopPolicy())
asyncio.run(main())
