import threading
import uvicorn
import config
from time import sleep
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from constants import Const
from utils.log_config import setup_logging
from routers import ping, intents, iandt, dashboard, stats
from pipeline import IntentPipeline
from controllers.mitigations_controller import MitigationsController

"""
This code is executed when applications starts
It bootstraps a loop that process the intents in background
"""

logger = setup_logging(__name__)

"""
The pipeline is satefull, so it should existst during the whole application lifecycle
"""
pipeline = IntentPipeline()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the loop that processes intents
    # Start threads
    t_intent = threading.Thread(target=process_intents, daemon=True)
    t_intent.start()
    # Start processing requests
    yield
    # Stop running threads
    t_intent.join(1)

"""
IBI API Server
"""
app = FastAPI(lifespan=lifespan)
app.include_router(dashboard.router, prefix="")
app.include_router(ping.router)
app.include_router(intents.router)
app.include_router(iandt.router)
app.include_router(stats.router)

# Register static files
app.mount("/static", StaticFiles(directory="app/dashboard/static"), name="static")

"""
Backround taks
"""
def process_intents():
    # pipeline = IntentPipeline()
    sleep(10)
    while(True):
        # logger.info("hello world from intents loop")
        try:
            # Process intents
            pipeline.process_intents()
        except Exception as e:
            logger.error(f"Error processing intent: {e}")
            raise e
        sleep(Const.THREAD_INTENT_WAIT)
    

def populate_database():
    """
    Populate data in Mitigation actions
    """
    MitigationsController.populate_mitigation_actions()
    MitigationsController.dump_mitigation_actions
    

"""
Main entry point
"""
if __name__ == "__main__":
    populate_database()
    uvicorn.run(app, host=Const.APP_HOST, port=Const.APP_PORT)