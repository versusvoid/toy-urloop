#!/usr/bin/env python3

import asyncio
from aiohttp import web

import urloop


async def handle(request):
    name = request.match_info.get('name', "Anonymous")
    text = "Hello, " + name
    return web.Response(text=text)


async def handle_file(request):
    return web.FileResponse(__file__)


class NLResponse(web.StreamResponse):
    def __init__(self, path: str):
        super().__init__()
        self._path = path
        self.content_type = 'text/plain; charset=UTF-8'

    async def prepare(self, request: web.BaseRequest):
        writer = await super().prepare(request)
        assert writer is not None

        async with await urloop.open(self._path) as f:
            i = 0
            async for line in f:
                i += 1
                await writer.write(f'{i: 3}:'.encode())
                await writer.write(line.upper().encode())

        await self.write_eof()


async def handle_nl(request):
    return NLResponse(__file__)


app = web.Application()
app.add_routes([
    web.get('/file', handle_file),
    web.get('/nl', handle_nl),
    web.get('/greet/{name}', handle),
])

if __name__ == '__main__':
    asyncio.set_event_loop_policy(urloop.URingEventLoopPolicy())
    web.run_app(app)
