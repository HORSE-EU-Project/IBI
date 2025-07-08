import threading
import uvicorn
import config
from time import sleep
from contextlib import asynccontextmanager
from fastapi import FastAPI
from constants import Const
from utils.log_config import setup_logging
from routers import ping, intents
from db.elastic_search import ElasticSearchClient
from pipeline import IntentPipeline

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
app.include_router(ping.router)
app.include_router(intents.router)

"""
Backround taks
"""
def process_intents():
    logger = setup_logging(__name__)
    pipeline = IntentPipeline()
    while(True):
        # logger.info("hello world from intents loop")
        try:
            # Process intents
            pipeline.process_intents()
        except Exception as e:
            logger.error(f"Error processing intents: {e}")
        sleep(Const.THREAD_INTENT_WAIT)
    

def clean_database():
    """
    Flush data in Elasticsearch
    """
    es_client = ElasticSearchClient()
    es_client.delete_indices()

def populate_database():
    """
    Populate data in Elasticsearch
    """
    es_client = ElasticSearchClient()
    es_client.pupulate_mitigations()

"""
Main entry point
"""
if __name__ == "__main__":
    # Flush data in Elasticsearch
    if config.ES_CLEAN:
        clean_database()
        # Populate data in Elasticsearch
        populate_database()
    uvicorn.run(app, host=Const.APP_HOST, port=Const.APP_PORT)