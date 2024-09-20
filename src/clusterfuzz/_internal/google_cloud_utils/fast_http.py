import asyncio
import aiohttp
import multiprocessing
import os
import uuid

async def download_file(session, url, filename):
    async with session.get(url) as response:
        with open(os.path.join('/tmp/fast/', filename), 'wb') as f:
            while True:
                chunk = await response.content.read(1024)
                if not chunk:
                    break
                f.write(chunk)
    
async def download_files(urls):
    async with aiohttp.ClientSession() as session:
        tasks = []
        x = str(uuid.uuid4())
        for i, url in enumerate(urls):
            filename = f"{x}_{i}.dat"n
            task = asyncio.create_task(download_file(session, url, filename))
            tasks.append(task)
        await asyncio.gather(*tasks)

def process_worker(urls):
    asyncio.run(download_files(urls))

def fast_download(all_urls, num_processes=16):
    print('len', len(all_urls))
    chunk_size = len(all_urls) // num_processes
    url_chunks = [all_urls[i:i+chunk_size] for i in range(0, len(all_urls), chunk_size)]
    
    with multiprocessing.Pool(num_processes) as pool:
        pool.map(process_worker, url_chunks)

if __name__ == "__main__":
    fast_download(urls)
