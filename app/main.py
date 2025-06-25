import threading
from time import sleep
from contextlib import asynccontextmanager
from fastapi import FastAPI
from constants import Const
from utils.log_config import setup_logging
from routers import ping, intents

"""
This code is executed when applications starts
It bootstraps a loop that process the intents in background
"""
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize logging
    setup_logging()
    # Initialize the loop that processes intents
    # Start threads
    threading.Thread(target=process_intents, daemon=True).start()
    # Start processing requests
    yield
    # Stop background tasks

"""
IBI API Server
"""
app = FastAPI(lifespan=lifespan)
app.include_router(ping.router)
app.include_router(intents.router)

"""
Backround taks
"""
def process_intents():
    logger = setup_logging()
    while(True):
        # logger.info("hello world from intents loop")
        sleep(Const.TH_INTENT_WAIT)
    

"""
Main entry point
"""
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=Const.SERVER_HOST, port=Const.SERVER_PORT)